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

	if err := forward([]string{"-listen", taken.Addr().String(), "-key", file}); err == nil {
		t.Fatal("forward returned without an error on an address that is taken")
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

func TestForwarderCarriesNoMoreConnectionsThanAWorkerJoins(t *testing.T) {
	node, port := loopback(t)
	f := keyedForwarder(unix.VMADDR_CID_LOCAL, port)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
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

	for range maxStreams {
		client()
		select {
		case <-dialled:
		case <-time.After(budget):
			t.Fatalf("fewer than %d connections reached the node", maxStreams)
		}
	}
	extra := client()
	refused := make(chan struct{})
	go func() {
		extra.Read(make([]byte, 1))
		close(refused)
	}()
	select {
	case <-dialled:
		t.Fatalf("connection %d reached the node", maxStreams+1)
	case <-refused:
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
