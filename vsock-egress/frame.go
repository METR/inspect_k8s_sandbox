package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// maxFrame is the most payload toFrames puts in a frame: with its 4-byte length, a full frame is one 64 KiB vsock packet.
const maxFrame = 64<<10 - 4

// A stream holds one of each while it lasts: without the pools every connection would allocate 128 KiB.
var (
	chunks  = sync.Pool{New: func() any { return new([4 + maxFrame]byte) }}
	readers = sync.Pool{New: func() any { return bufio.NewReaderSize(nil, 4+maxFrame) }}
)

// timed is the vsock end of a stream, with the deadline its opening may have left it.
type timed interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
}

// join carries one TCP connection over a vsock connection as frames: Firecracker passes no half-close on, so each direction ends with an empty frame.
func join(vsock timed, tcp *net.TCPConn, pace *pacer, stall time.Duration) {
	// The time each end had to say what it wants ends here: left on, it would end the stream.
	vsock.SetDeadline(time.Time{})
	tcp.SetDeadline(time.Time{})
	var running sync.WaitGroup
	var shut atomic.Bool // this side has closed its writes to tcp
	sent, received, gone := make(chan error, 1), make(chan error, 1), make(chan struct{})
	running.Add(2)
	go func() {
		defer running.Done()
		sent <- toFrames(vsock, unreset{tcp, &shut}, pace)
	}()
	go func() {
		defer running.Done()
		err := fromFrames(bounded{tcp, stall}, vsock, pace)
		if err == nil {
			shut.Store(true)
			err = tcp.CloseWrite()
		}
		received <- err
		if err == nil {
			vsock.Read(make([]byte, 1)) // nothing follows the last frame: this returns when the vsock closes
			close(gone)
		}
	}()
	var err error
	select {
	case err = <-sent:
		if err == nil {
			err = <-received
		}
	case err = <-received:
		if err == nil {
			select {
			case err = <-sent:
			case <-gone: // the peer has gone, unless this side's last frame had just reached it
				tcp.SetReadDeadline(time.Now())
				err = <-sent
			}
		}
	}
	if err != nil || stall > 0 && !taken(tcp, stall) {
		tcp.SetLinger(0)
	}
	tcp.Close()
	vsock.Close()
	running.Wait()
}

// taken waits, for wait at most, until the peer has acknowledged all that tcp sent it and its end: closed sooner, the kernel keeps the socket and what is unsent for minutes after its stream's place is free.
func taken(tcp *net.TCPConn, wait time.Duration) (all bool) {
	raw, _ := tcp.SyscallConn() // it fails for a nil connection alone
	for pause, end := time.Millisecond, time.Now().Add(wait); ; pause = min(2*pause, 100*time.Millisecond) {
		all = true // where the kernel does not say, the close is as it was
		raw.Control(func(fd uintptr) {
			if info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
				all = info.State == unix.BPF_TCP_CLOSE // the kernel's TCP_CLOSE: each end is acknowledged, or the peer has reset
			}
		})
		if all || !time.Now().Before(end) {
			return all
		}
		time.Sleep(pause)
	}
}

// bounded gives each write to its connection wait at most: a peer that takes nothing would else keep both of a stream's pumps waiting on it after the stream's other end had gone.
type bounded struct {
	*net.TCPConn
	wait time.Duration
}

func (b bounded) Write(p []byte) (int, error) {
	if b.wait > 0 {
		b.SetWriteDeadline(time.Now().Add(b.wait))
	}
	return b.TCPConn.Write(p)
}

// unreset reads the end of a connection its peer reset as the error it is: the kernel gives a reset to one waiting call alone, and where a write takes it the read sees an end.
type unreset struct {
	*net.TCPConn
	shut *atomic.Bool // this side has ended its writes: none waits then, and a clean end leaves the connection closed too
}

func (u unreset) Read(p []byte) (int, error) {
	n, err := u.TCPConn.Read(p)
	// A peer that left Nagle on holds its next small write until these bytes are acknowledged, which the kernel puts off 40 ms once replies flow back; asked after each read, since the option does not last.
	if raw, failed := u.SyscallConn(); failed == nil {
		raw.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 1) })
	}
	if err == io.EOF {
		// Refused once the connection is closed, as a reset leaves it; asked before shut is read, so this side's own end cannot come between.
		if closed := u.CloseRead(); closed != nil && !u.shut.Load() && !u.endedFirst() {
			err = closed
		}
	}
	return n, err
}

// endedFirst says whether a reset came after the peer had ended its side, which leaves the reply whole: the kernel then holds EPIPE for the socket, and ECONNRESET for a reset alone.
func (u unreset) endedFirst() (ended bool) {
	if raw, err := u.SyscallConn(); err == nil {
		raw.Control(func(fd uintptr) {
			held, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_ERROR)
			ended = err == nil && held == int(syscall.EPIPE)
		})
	}
	return ended
}

// toFrames copies src to dst as frames, each a 4-byte length and that many bytes, then an empty frame.
func toFrames(dst io.Writer, src io.Reader, pace *pacer) error {
	buf := chunks.Get().(*[4 + maxFrame]byte)
	defer chunks.Put(buf)
	for {
		n, err := src.Read(buf[4:])
		if n > 0 {
			pace.wait(n)
			binary.BigEndian.PutUint32(buf[:], uint32(n))
			if _, err := dst.Write(buf[:4+n]); err != nil {
				return err
			}
		}
		if err == io.EOF {
			_, err = dst.Write([]byte{0, 0, 0, 0})
			return err
		}
		if err != nil {
			return err
		}
	}
}

// fromFrames copies frames from src to dst until the empty frame, each part of a frame as it arrives; a stream that ends before it is an error.
func fromFrames(dst io.Writer, src io.Reader, pace *pacer) error {
	r := readers.Get().(*bufio.Reader)
	r.Reset(src)
	defer func() {
		r.Reset(nil)
		readers.Put(r)
	}()
	for {
		length, err := r.Peek(4)
		if err != nil {
			return err
		}
		left := binary.BigEndian.Uint32(length)
		r.Discard(4)
		if left == 0 {
			return nil
		}
		for left > 0 {
			if _, err := r.Peek(1); err != nil { // waits for more of the frame
				return err
			}
			part, _ := r.Peek(int(min(left, uint32(r.Buffered())))) // a peer may claim a frame of any length: it is passed on like several
			pace.wait(len(part))
			if _, err := dst.Write(part); err != nil {
				return err
			}
			r.Discard(len(part))
			left -= uint32(len(part))
		}
	}
}

// paceSlack is how far ahead of its rate a pacer lets bytes run before it sleeps: short messages never wait.
const paceSlack = 10 * time.Millisecond

// pacer holds what passes it, bytes or new streams, to a rate. A nil pacer holds nothing back.
type pacer struct {
	rate  float64 // a second
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
	if idle := now.Add(-paceSlack); p.paid.Before(idle) {
		p.paid = idle // a sleep that ran late is made up, an idle spell is not saved up
	}
	p.paid = p.paid.Add(time.Duration(float64(n) / p.rate * float64(time.Second)))
	owed := p.paid.Sub(now)
	p.mu.Unlock()
	if owed > paceSlack {
		p.sleep(owed)
	}
}
