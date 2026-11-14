package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// firecracker stands in for a VM's vsock socket on the node: it answers CONNECT for a guest port with what a
// guest process listening there would say first.
func firecracker(t *testing.T, says map[uint32]string) (vsock string) {
	t.Helper()
	vsock = filepath.Join(t.TempDir(), "vm.vsock")
	l, err := net.Listen("unix", vsock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			var port uint32
			fmt.Fscanf(bufio.NewReader(c), "CONNECT %d\n", &port)
			if say, ok := says[port]; ok { // with no listener in the guest, Firecracker closes without a word
				fmt.Fprintf(c, "OK 1073741824\n%s", say)
			}
			c.Close()
		}
	}()
	return vsock
}

// proxy is a TCP server that hands over each connection it accepts.
func proxy(t *testing.T) (address string, accepted chan net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	accepted = make(chan net.Conn, 2*maxStreams)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			accepted <- c
		}
	}()
	return l.Addr().String(), accepted
}

// served starts a worker for a VM whose forwarder holds key, and returns a dial for the guest's side.
func served(t *testing.T, key []byte, target string, pace *pacer) (dial func() net.Conn) {
	t.Helper()
	vsock := firecracker(t, map[uint32]string{keyPort: string(key)})
	w := newWorker(vsock, target, 0)
	w.pace = pace
	streams := fmt.Sprintf("%s_%d", vsock, streamPort)
	l, err := net.Listen("unix", streams)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go w.serve(l)
	return func() net.Conn {
		c, err := net.Dial("unix", streams)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(budget))
		t.Cleanup(func() { c.Close() })
		return c
	}
}

// closed is closed when the worker has closed c.
func closed(c net.Conn) chan struct{} {
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, c)
		close(done)
	}()
	return done
}

func newKey() []byte {
	key := make([]byte, keySize)
	rand.Read(key)
	return key
}

func TestStreamWithoutTheKeyReachesNothing(t *testing.T) {
	key := newKey()
	target, accepted := proxy(t)
	dial := served(t, key, target, nil)

	intruder := dial() // a workload process that opened the vsock itself
	intruder.Write(append(newKey(), frame("CONNECT evil.example:443 HTTP/1.1\r\n\r\n")...))
	select {
	case <-accepted:
		t.Fatal("a stream that did not open with the key reached the proxy")
	case <-closed(intruder):
	case <-time.After(budget):
		t.Fatal("the stream was neither refused nor joined")
	}

	forwarder := dial()
	forwarder.Write(append(key, frame("ping")...))
	select {
	case c := <-accepted:
		got := make([]byte, 4)
		c.SetDeadline(time.Now().Add(budget))
		if _, err := io.ReadFull(c, got); string(got) != "ping" {
			t.Fatalf("the proxy read %q, %v", got, err)
		}
	case <-time.After(budget):
		t.Fatal("a stream that opened with the key did not reach the proxy")
	}
}

func TestStreamPastTheCapIsRefused(t *testing.T) {
	key := newKey()
	target, accepted := proxy(t)
	dial := served(t, key, target, nil)

	open := make([]net.Conn, maxStreams)
	for i := range open {
		open[i] = dial()
		open[i].Write(key)
	}
	for range open {
		select {
		case <-accepted:
		case <-time.After(budget):
			t.Fatalf("fewer than %d streams reached the proxy", maxStreams)
		}
	}
	extra := dial()
	extra.Write(key)
	select {
	case <-accepted:
		t.Fatalf("stream %d reached the proxy", maxStreams+1)
	case <-closed(extra):
	case <-time.After(budget):
		t.Fatalf("stream %d was neither refused nor joined", maxStreams+1)
	}

	open[0].Close() // its slot comes back once the worker has seen the close
	for deadline := time.Now().Add(budget); ; {
		next := dial()
		next.Write(key)
		select {
		case <-accepted:
			return
		case <-closed(next):
		}
		if time.Now().After(deadline) {
			t.Fatal("no stream was let in after one had ended")
		}
	}
}

func TestWorkerHoldsItsStreamsToTheRate(t *testing.T) {
	var mu sync.Mutex
	clock, slept := time.Unix(0, 0), time.Duration(0)
	const rate, sent = 1 << 20, 8 << 20
	pace := &pacer{rate: rate, now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}, sleep: func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		clock, slept = clock.Add(d), slept+d
	}}
	key := newKey()
	target, accepted := proxy(t)
	c := served(t, key, target, pace)()

	go func() {
		c.Write(key)
		toFrames(c, io.LimitReader(zeros{}, sent), nil)
	}()
	up := <-accepted
	up.SetDeadline(time.Now().Add(budget))
	if n, err := io.Copy(io.Discard, up); n != sent || err != nil {
		t.Fatalf("the proxy read %d bytes, %v: want %d", n, err, sent)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := sent / rate * time.Second; slept < want-paceSlack || slept > want {
		t.Fatalf("carrying %d bytes at %d a second slept %v: want %v, less at most %v", sent, rate, slept, want, paceSlack)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "work" { // the launcher's test starts this binary as a worker
		main()
		return
	}
	os.Exit(m.Run())
}
