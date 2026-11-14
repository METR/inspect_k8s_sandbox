package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// maxFrame bounds a frame's payload, so that a peer's length never sizes a buffer.
const maxFrame = 64 << 10

var errFrame = errors.New("frame longer than the bound")

// join carries one TCP connection over a vsock connection, as frames. Firecracker passes no half-close on,
// so each direction ends with an empty frame and the vsock connection closes only when both have ended.
// A stream cut short reaches the TCP peer as a reset, never as a clean end.
func join(vsock io.ReadWriteCloser, tcp *net.TCPConn, pace *pacer) {
	ended := make(chan error, 2)
	go func() { ended <- toFrames(vsock, tcp, pace) }()
	go func() {
		err := fromFrames(tcp, vsock, pace)
		if err == nil {
			err = tcp.CloseWrite()
		}
		ended <- err
	}()
	err := <-ended
	if err == nil {
		err = <-ended
	}
	if err != nil {
		tcp.SetLinger(0)
	}
	tcp.Close()
	vsock.Close()
}

// toFrames copies src to dst as frames, each a 4-byte length and that many bytes, then an empty frame.
func toFrames(dst io.Writer, src io.Reader, pace *pacer) error {
	buf := make([]byte, 4+maxFrame)
	for {
		n, err := src.Read(buf[4:])
		if n > 0 {
			pace.wait(n)
			binary.BigEndian.PutUint32(buf, uint32(n))
			if _, err := dst.Write(buf[:4+n]); err != nil {
				return err
			}
		}
		if err == io.EOF {
			_, err = dst.Write(make([]byte, 4))
			return err
		}
		if err != nil {
			return err
		}
	}
}

// fromFrames copies frames from src to dst until the empty frame. A stream that ends before it is an error.
func fromFrames(dst io.Writer, src io.Reader, pace *pacer) error {
	buf := make([]byte, maxFrame)
	for {
		if _, err := io.ReadFull(src, buf[:4]); err != nil {
			return err
		}
		n := binary.BigEndian.Uint32(buf)
		if n == 0 {
			return nil
		}
		if n > maxFrame {
			return errFrame
		}
		if _, err := io.ReadFull(src, buf[:n]); err != nil {
			return err
		}
		pace.wait(int(n))
		if _, err := dst.Write(buf[:n]); err != nil {
			return err
		}
	}
}

// paceSlack is how far ahead of its rate a pacer lets bytes run before it sleeps: short messages never wait.
const paceSlack = 10 * time.Millisecond

// pacer holds the bytes that pass it to a rate. A nil pacer holds nothing back.
type pacer struct {
	rate  float64 // bytes a second
	now   func() time.Time
	sleep func(time.Duration)

	mu   sync.Mutex
	paid time.Time // when the bytes let through so far will have been paid for
}

func newPacer(rate int) *pacer {
	if rate <= 0 {
		return nil
	}
	return &pacer{rate: float64(rate), now: time.Now, sleep: time.Sleep}
}

func (p *pacer) wait(n int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	now := p.now()
	if p.paid.Before(now) {
		p.paid = now
	}
	p.paid = p.paid.Add(time.Duration(float64(n) / p.rate * float64(time.Second)))
	owed := p.paid.Sub(now)
	p.mu.Unlock()
	if owed > paceSlack {
		p.sleep(owed)
	}
}
