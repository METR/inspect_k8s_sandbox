package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// loopback listens on a free vsock port of this machine, which a test reaches at VMADDR_CID_LOCAL.
func loopback(t *testing.T) (*vsockListener, uint32) {
	t.Helper()
	l, err := vsockListen(unix.VMADDR_PORT_ANY)
	if err != nil {
		t.Skipf("no AF_VSOCK here: %v", err)
	}
	t.Cleanup(func() { l.f.Close() })
	raw, _ := l.f.SyscallConn()
	var port uint32
	raw.Control(func(fd uintptr) {
		if sa, err := unix.Getsockname(int(fd)); err == nil {
			port = sa.(*unix.SockaddrVM).Port
		}
	})
	c, err := vsockDial(unix.VMADDR_CID_LOCAL, port)
	if err != nil {
		t.Skipf("no vsock loopback here (modprobe vsock_loopback): %v", err)
	}
	c.Close()
	if c, _, err = l.accept(); err != nil {
		t.Fatal(err)
	}
	c.Close()
	return l, port
}

func TestRestartedForwarderKeepsItsKey(t *testing.T) {
	file := filepath.Join(t.TempDir(), "key")
	var first, second, elsewhere forwarder
	for f, file := range map[*forwarder]string{&first: file, &elsewhere: file + ".other"} {
		if err := f.loadKey(file); err != nil {
			t.Fatal(err)
		}
	}
	if err := second.loadKey(file); err != nil {
		t.Fatal(err)
	}
	if first.key != second.key || first.key == elsewhere.key || first.key == [keySize]byte{} {
		t.Fatal("want one random key for each key file, the same every time the file is loaded")
	}
}

func TestForwarderThatCannotListenIsNotReady(t *testing.T) {
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	file := filepath.Join(t.TempDir(), "key")
	os.WriteFile(file+readySuffix, nil, 0o600) // left by the forwarder before this one

	var listen *net.OpError
	if err := forward([]string{"-listen", taken.Addr().String(), "-key", file}); !errors.As(err, &listen) {
		t.Skipf("forward did not come to listen on its proxy port: %v", err)
	}
	if err := ready([]string{"-key", file}); err == nil {
		t.Fatal("ready passed for a forwarder that does not listen")
	}
}

func keyedForwarder(host, port uint32) *forwarder {
	f := newForwarder(host, port)
	rand.Read(f.key[:])
	return f
}

func TestKeyIsServedToTheNodeAlone(t *testing.T) {
	for name, tc := range map[string]struct {
		node   uint32 // the CID the forwarder takes for the node's; the test's own connections come from VMADDR_CID_LOCAL
		served bool
	}{
		"a process in the VM": {node: hostCID, served: false},
		"the node":            {node: unix.VMADDR_CID_LOCAL, served: true},
	} {
		t.Run(name, func(t *testing.T) {
			l, port := loopback(t)
			f := keyedForwarder(tc.node, 0)
			go f.serveKey(l)
			c, err := vsockDial(unix.VMADDR_CID_LOCAL, port)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(budget))
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatal(err)
			}
			if served := bytes.Equal(got, f.key[:]); served != tc.served || !served && len(got) > 0 {
				t.Fatalf("the peer read %d bytes, the key: %v; want the key: %v", len(got), served, tc.served)
			}
		})
	}
}

// proxyPort serves f's proxy port on loopback and returns a connection to it, as a program in the sandbox makes.
func proxyPort(t *testing.T, f *forwarder) *net.TCPConn {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go f.serve(l)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(budget))
	return c.(*net.TCPConn)
}

func TestConnectionOpensWithTheKeyAndEndsEachWayInTheStream(t *testing.T) {
	node, port := loopback(t)
	f := keyedForwarder(unix.VMADDR_CID_LOCAL, port)
	client := proxyPort(t, f)
	client.Write([]byte("request"))
	client.CloseWrite()

	up, _, err := node.accept()
	if err != nil {
		t.Fatal(err)
	}
	defer up.Close()
	up.SetDeadline(time.Now().Add(budget))
	key := make([]byte, keySize)
	if _, err := io.ReadFull(up, key); err != nil || !bytes.Equal(key, f.key[:]) {
		t.Fatalf("the stream did not open with the forwarder's key (%v)", err)
	}
	var request bytes.Buffer
	if err := fromFrames(&request, up, nil); err != nil || request.String() != "request" {
		t.Fatalf("the node read %q, %v: want the request and then its end", request.String(), err)
	}
	if err := toFrames(up, strings.NewReader("reply"), nil); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(client); string(got) != "reply" || err != nil {
		t.Fatalf("the client read %q, %v: want the reply and then a clean end", got, err)
	}
}

func TestConnectionPastTheCapWaitsForAPlace(t *testing.T) {
	node, port := loopback(t)
	f := keyedForwarder(unix.VMADDR_CID_LOCAL, port)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	over := make(chan int, 2*maxStreams)
	f.connect = func(cid, port uint32) (*os.File, error) {
		if carried := len(f.slots); carried > maxStreams {
			over <- carried
		}
		return vsockDial(cid, port)
	}
	go f.serve(l)
	dialled := make(chan *os.File, 2*maxStreams)
	go func() {
		for {
			c, _, err := node.accept()
			if errors.Is(err, os.ErrClosed) {
				return
			}
			if err != nil {
				t.Logf("accept: %v", err)
				continue
			}
			t.Cleanup(func() { c.Close() })
			dialled <- c
		}
	}()
	client := func() net.Conn {
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(budget))
		return c
	}

	first := client()
	var onNode *os.File
	select {
	case onNode = <-dialled:
	case <-time.After(budget):
		t.Fatal("the first connection did not reach the node")
	}
	for range maxStreams - 1 {
		client()
		select {
		case <-dialled:
		case <-time.After(budget):
			t.Fatalf("fewer than %d connections reached the node", maxStreams)
		}
	}
	extra := client()
	reset := make(chan struct{})
	go func() {
		extra.Read(make([]byte, 1))
		close(reset)
	}()
	first.Close() // one stream ends, both ways: its place is the waiting connection's
	onNode.Write([]byte{0, 0, 0, 0})
	select {
	case <-dialled:
	case <-reset:
		t.Fatalf("connection %d was reset: a client that keeps %d connections busy fails", maxStreams+1, maxStreams)
	case <-time.After(budget):
		t.Fatal("the waiting connection never got a place")
	}
	if len(over) > 0 {
		t.Fatalf("%d connections were carried at once: the cap is %d", <-over, maxStreams)
	}
}

func TestConnectionPastTheWaitingBoundIsReset(t *testing.T) {
	f := keyedForwarder(0, 0)
	for range maxStreams { // it carries all it may,
		f.slots <- struct{}{}
	}
	for range maxStreams + maxWaiting { // and holds back all it may
		f.queue <- struct{}{}
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go f.serve(l)
	c, err := net.Dial("tcp", l.Addr().String()) // the reset may be there before the dial returns
	if err == nil {
		t.Cleanup(func() { c.Close() })
		c.SetReadDeadline(time.Now().Add(handshakeWait / 2)) // a connection held back is reset as well, after handshakeWait
		_, err = c.Read(make([]byte, 1))
	}
	if !errors.Is(err, unix.ECONNRESET) {
		t.Fatalf("a connection past the %d held back ended with %v: want a reset at once", maxWaiting, err)
	}
}

// lagging makes f reach w as through a Firecracker that is slow to tell the node of a stream's end: what f closes stays open on w until held is closed.
func lagging(t *testing.T, f *forwarder, w *worker, held chan struct{}) {
	dial := serve(t, w)
	f.connect = func(uint32, uint32) (*os.File, error) {
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			return nil, err
		}
		guest, relay, node := os.NewFile(uintptr(pair[0]), "vsock"), os.NewFile(uintptr(pair[1]), "relay"), dial()
		go io.Copy(relay, node)
		go func() {
			io.Copy(node, relay)
			<-held
			node.Close()
			relay.Close()
		}()
		return guest, nil
	}
}

func TestStreamsTheGuestDroppedDoNotShutOutTheNext(t *testing.T) {
	target, accepted := proxy(t)
	f := keyedForwarder(0, 0)
	held := make(chan struct{})
	t.Cleanup(func() { close(held) })
	lagging(t, f, newWorker(firecracker(t, map[uint32]string{keyPort: string(f.key[:])}), target, 0), held)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go f.serve(l)

	for _, round := range []string{"first", "next"} {
		clients := make([]*net.TCPConn, maxStreams)
		for i := range clients {
			c, err := net.Dial("tcp", l.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { c.Close() })
			clients[i] = c.(*net.TCPConn)
		}
		for range clients {
			within(t, accepted, fmt.Sprintf("way to the proxy for one of the %s %d streams", round, maxStreams))
		}
		for _, c := range clients { // dropped, not ended: the forwarder lets go at once, the node learns of it late
			c.SetLinger(0)
			c.Close()
		}
	}
}

func TestConnectionWaitsOutAWorkerThatIsStarting(t *testing.T) {
	node, port := loopback(t)
	f := keyedForwarder(unix.VMADDR_CID_LOCAL, port)
	starting := true // the first connection finds no worker listening, as while one is being started
	f.connect = func(cid, port uint32) (*os.File, error) {
		if starting {
			starting = false
			return nil, fmt.Errorf("vsock connect: %w", unix.ECONNRESET)
		}
		return vsockDial(cid, port)
	}
	client := proxyPort(t, f)
	refused := make(chan error, 1)
	go func() {
		_, err := client.Read(make([]byte, 1))
		refused <- err
	}()
	arrived := make(chan error, 1)
	go func() {
		c, _, err := node.accept()
		if err == nil {
			t.Cleanup(func() { c.Close() }) // held open: closing it now would end the client's connection too
		}
		arrived <- err
	}()
	select {
	case err := <-arrived:
		if err != nil {
			t.Fatal(err)
		}
	case err := <-refused:
		t.Fatalf("the client's connection ended (%v) before the worker was up", err)
	}
}
