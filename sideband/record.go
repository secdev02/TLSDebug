package sideband

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Direction is which leg of the intercept a packet belongs to.
type Direction uint8

const (
	DirClientToProxy Direction = 1
	DirProxyToClient Direction = 2
	DirProxyToOrigin Direction = 3
	DirOriginToProxy Direction = 4
)

func (d Direction) String() string {
	switch d {
	case DirClientToProxy:
		return "client_to_proxy"
	case DirProxyToClient:
		return "proxy_to_client"
	case DirProxyToOrigin:
		return "proxy_to_origin"
	case DirOriginToProxy:
		return "origin_to_proxy"
	default:
		return "unknown"
	}
}

// Layer distinguishes ciphertext on the socket from bytes after termination.
type Layer uint8

const (
	LayerWire  Layer = 0
	LayerPlain Layer = 1
)

func (l Layer) String() string {
	if l == LayerPlain {
		return "plaintext"
	}
	return "wire"
}

// Proto is the Sideband protocol that produced a record.
type Proto uint16

const (
	ProtoTCP       Proto = 1
	ProtoUDP       Proto = 2
	ProtoTLS       Proto = 3
	ProtoSTARTTLS  Proto = 4
	ProtoDTLS      Proto = 5
	ProtoQUIC      Proto = 6
	ProtoWireGuard Proto = 7
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoTLS:
		return "tls"
	case ProtoSTARTTLS:
		return "starttls"
	case ProtoDTLS:
		return "dtls"
	case ProtoQUIC:
		return "quic"
	case ProtoWireGuard:
		return "wireguard"
	default:
		return "unknown"
	}
}

const (
	binMagic      = "SBND"
	binVersion    = 1
	jsonInlineMax = 4096
	recordHeader  = 8 + 4 + 1 + 1 + 2 + 4
)

// Record is one packet or chunk. Payload is the exact bytes in the binary log.
type Record struct {
	Time      time.Time
	FlowID    uint32
	Direction Direction
	Layer     Layer
	Proto     Proto
	Payload   []byte
	Fields    map[string]any
}

type jsonRecord struct {
	Time       string         `json:"ts"`
	FlowID     uint32         `json:"flow"`
	Direction  string         `json:"dir"`
	Layer      string         `json:"layer"`
	Proto      string         `json:"proto"`
	Fields     map[string]any `json:"fields,omitempty"`
	BinOffset  int64          `json:"bin_offset"`
	BinLength  int            `json:"bin_length"`
	PayloadB64 string         `json:"payload_b64,omitempty"`
}

// Logger appends packets.bin and packets.jsonl. Both are mode 0600.
// JSON names the bytes by offset and length. Payloads up to 4 KiB are also
// inlined so a reader can see a small record without opening the binary file.
type Logger struct {
	mu   sync.Mutex
	bin  *os.File
	js   *os.File
	keys *os.File
	off  int64
}

// OpenLogger creates or appends the two logs in dir.
func OpenLogger(dir string) (*Logger, error) {
	binPath := dir + "/packets.bin"
	jsPath := dir + "/packets.jsonl"
	bin, err := os.OpenFile(binPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := bin.Chmod(0600); err != nil {
		bin.Close()
		return nil, err
	}
	info, err := bin.Stat()
	if err != nil {
		bin.Close()
		return nil, err
	}
	if info.Size() == 0 {
		hdr := make([]byte, 8)
		copy(hdr, binMagic)
		binary.LittleEndian.PutUint32(hdr[4:], binVersion)
		if _, err := bin.Write(hdr); err != nil {
			bin.Close()
			return nil, err
		}
	}
	js, err := os.OpenFile(jsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		bin.Close()
		return nil, err
	}
	if err := js.Chmod(0600); err != nil {
		js.Close()
		bin.Close()
		return nil, err
	}
	keys, err := os.OpenFile(dir+"/sideband.keys", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		js.Close()
		bin.Close()
		return nil, err
	}
	if err := keys.Chmod(0600); err != nil {
		keys.Close()
		js.Close()
		bin.Close()
		return nil, err
	}
	off, err := bin.Seek(0, 2)
	if err != nil {
		keys.Close()
		js.Close()
		bin.Close()
		return nil, err
	}
	return &Logger{bin: bin, js: js, keys: keys, off: off}, nil
}

// Write stores one record. A copy of the payload is taken so the caller can reuse the buffer.
func (l *Logger) Write(rec Record) error {
	if l == nil {
		return nil
	}
	payload := append([]byte(nil), rec.Payload...)
	hdr := make([]byte, recordHeader)
	ts := rec.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	binary.LittleEndian.PutUint64(hdr[0:], uint64(ts.UnixNano()))
	binary.LittleEndian.PutUint32(hdr[8:], rec.FlowID)
	hdr[12] = byte(rec.Direction)
	hdr[13] = byte(rec.Layer)
	binary.LittleEndian.PutUint16(hdr[14:], uint16(rec.Proto))
	binary.LittleEndian.PutUint32(hdr[16:], uint32(len(payload)))

	l.mu.Lock()
	defer l.mu.Unlock()

	payloadAt := l.off + int64(recordHeader)
	if _, err := l.bin.Write(hdr); err != nil {
		return err
	}
	if _, err := l.bin.Write(payload); err != nil {
		return err
	}
	l.off += int64(recordHeader + len(payload))

	jr := jsonRecord{
		Time:      ts.UTC().Format(time.RFC3339Nano),
		FlowID:    rec.FlowID,
		Direction: rec.Direction.String(),
		Layer:     rec.Layer.String(),
		Proto:     rec.Proto.String(),
		Fields:    rec.Fields,
		BinOffset: payloadAt,
		BinLength: len(payload),
	}
	if len(payload) > 0 && len(payload) <= jsonInlineMax {
		jr.PayloadB64 = base64.StdEncoding.EncodeToString(payload)
	}
	line, err := json.Marshal(jr)
	if err != nil {
		return err
	}
	line = append(line, '\n')
	_, err = l.js.Write(line)
	return err
}

// Close flushes both files.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err1 := l.bin.Close()
	err2 := l.js.Close()
	var err3 error
	if l.keys != nil {
		err3 = l.keys.Close()
	}
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return err3
}

func stringsHasNewline(s string) bool {
	return len(s) > 0 && s[len(s)-1] == '\n'
}

// WriteSecrets appends private keys and NSS lines to sideband.keys.
func (l *Logger) WriteSecrets(text string) error {
	if l == nil || l.keys == nil || text == "" {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !stringsHasNewline(text) {
		text += "\n"
	}
	_, err := l.keys.WriteString(text)
	return err
}

// ReadPayload returns the bytes named by a JSON record. Used by tests and readers.
func ReadPayload(binPath string, offset int64, length int) ([]byte, error) {
	f, err := os.Open(binPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if n != length {
		return nil, fmt.Errorf("short payload read: %d", n)
	}
	return buf, err
}
