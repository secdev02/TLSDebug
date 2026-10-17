package sideband

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readRecords(t *testing.T, dir string) []jsonRecord {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "packets.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []jsonRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var rec jsonRecord
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("no packet records")
	}
	return out
}

func recordPayload(t *testing.T, dir string, rec jsonRecord) []byte {
	t.Helper()
	got, err := ReadPayload(filepath.Join(dir, "packets.bin"), rec.BinOffset, rec.BinLength)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func findRecord(recs []jsonRecord, proto string, payload []byte, dir string, t *testing.T) jsonRecord {
	t.Helper()
	for _, rec := range recs {
		if rec.Proto != proto || rec.BinLength != len(payload) {
			continue
		}
		if string(recordPayload(t, dir, rec)) == string(payload) {
			return rec
		}
	}
	t.Fatalf("no %s record with payload %q", proto, payload)
	return jsonRecord{}
}

func keysText(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "sideband.keys"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "sideband.keys"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("sideband.keys mode = %o", info.Mode().Perm())
	}
	return string(b)
}

func hasSecretLine(text string) bool {
	return strings.Contains(text, "TRAFFIC_SECRET") || strings.Contains(text, "CLIENT_RANDOM")
}
