package sideband

import (
	"io"
	"net"
	"sync"
)

// splice copies both directions and logs each chunk as plaintext.
// It returns when both copies finish. A closed peer is a normal end.
func splice(flow *Flow, proto Proto, left, right net.Conn) error {
	var wg sync.WaitGroup
	wg.Add(2)
	errc := make(chan error, 2)
	go func() {
		defer wg.Done()
		errc <- copyLog(flow, proto, DirClientToProxy, DirProxyToOrigin, left, right)
	}()
	go func() {
		defer wg.Done()
		errc <- copyLog(flow, proto, DirOriginToProxy, DirProxyToClient, right, left)
	}()
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil && err != io.EOF {
			return err
		}
	}
	return nil
}

func copyLog(flow *Flow, proto Proto, readDir, writeDir Direction, src, dst net.Conn) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			flow.Log(readDir, LayerPlain, proto, chunk, nil)
			if _, werr := dst.Write(chunk); werr != nil {
				return werr
			}
			flow.Log(writeDir, LayerPlain, proto, chunk, nil)
		}
		if err != nil {
			return err
		}
	}
}
