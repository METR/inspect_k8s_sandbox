package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
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
	if err := errors.Join(first.loadKey(file), elsewhere.loadKey(file+".other"), second.loadKey(file)); err != nil {
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
	go f.serve(l, f.proxied)
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
	go f.serve(l, f.proxied)
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

// refused serves f, dials it once, and reports how that connection ended and how many streams f opened to the node.
func refused(t *testing.T, f *forwarder) (ended error, streams int32) {
	t.Helper()
	var connects atomic.Int32
	f.connect = func(uint32, uint32) (*os.File, error) {
		connects.Add(1)
		return nil, errors.New("no node in this test")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go f.serve(l, f.proxied)
	c, err := net.Dial("tcp", l.Addr().String()) // a reset may be there before the dial returns
	if err == nil {
		t.Cleanup(func() { c.Close() })
		c.SetReadDeadline(time.Now().Add(budget))
		_, err = c.Read(make([]byte, 1))
	}
	return err, connects.Load()
}

func TestConnectionThatGetsNoPlaceIsResetWithNoStream(t *testing.T) {
	f := keyedForwarder(0, 0)
	f.wait = time.Millisecond
	for range maxStreams { // it carries all it may
		f.slots <- struct{}{}
	}
	if err, streams := refused(t, f); !errors.Is(err, unix.ECONNRESET) || streams != 0 {
		t.Fatalf("connection %d ended with %v after %d streams to the node: want a reset and none", maxStreams+1, err, streams)
	}
}

func TestConnectionPastTheWaitingBoundIsReset(t *testing.T) {
	f := keyedForwarder(0, 0)
	for range maxStreams + maxWaiting { // it holds back all it may, with a place free for the next it takes
		f.queue <- struct{}{}
	}
	if err, streams := refused(t, f); !errors.Is(err, unix.ECONNRESET) || streams != 0 {
		t.Fatalf("a connection past the %d held back ended with %v after %d streams to the node: want a reset and none", maxWaiting, err, streams)
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
	go f.serve(l, f.proxied)

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

// nodeEnd is a vsock listener whose connections take peerBuffer bytes at a time, as Firecracker does of a guest's.
func nodeEnd(t *testing.T) (*vsockListener, uint32) {
	t.Helper()
	node, port := loopback(t)
	listener, _ := node.f.SyscallConn()
	var err error
	listener.Control(func(fd uintptr) {
		err = unix.SetsockoptUint64(int(fd), unix.AF_VSOCK, unix.SO_VM_SOCKETS_BUFFER_SIZE, peerBuffer)
	})
	if err != nil {
		t.Fatal(err)
	}
	return node, port
}

// carrying accepts until a connection has a byte to read: an interrupted dial leaves an ended one first.
func carrying(t *testing.T, node *vsockListener, deadline time.Time) *os.File {
	t.Helper()
	node.f.SetDeadline(deadline)
	for {
		up, _, err := node.accept()
		if err != nil {
			t.Fatalf("no connection that carries a byte reached the node: %v", err)
		}
		up.SetReadDeadline(deadline)
		end, _ := up.SyscallConn()
		var n int
		end.Read(func(fd uintptr) bool {
			var errno error
			n, _, errno = unix.Recvfrom(int(fd), make([]byte, 1), unix.MSG_PEEK)
			return errno != unix.EAGAIN
		})
		if n > 0 {
			return up
		}
		up.Close()
	}
}

// atNode reads the stream a full buffer at a time: what the frames after skip carry, and how many cross a buffer's end.
func atNode(t *testing.T, up *os.File, skip int, deadline time.Time) (carried []byte, crossed int) {
	t.Helper()
	frames := func(stream []byte) (carried []byte, crossed int, ended bool) {
		for at := skip; at+4 <= len(stream); {
			length := int(binary.BigEndian.Uint32(stream[at:]))
			if length == 0 {
				return carried, crossed, true
			}
			if at+4+length > len(stream) {
				break
			}
			carried = append(carried, stream[at+4:at+4+length]...)
			if at/peerBuffer != (at+4+length-1)/peerBuffer {
				crossed++
			}
			at += 4 + length
		}
		return carried, crossed, false
	}
	var stream []byte
	end, _ := up.SyscallConn()
	queued := make([]byte, peerBuffer)
	for ; ; time.Sleep(time.Millisecond) {
		var n int
		end.Control(func(fd uintptr) { n, _, _ = unix.Recvfrom(int(fd), queued, unix.MSG_PEEK|unix.MSG_DONTWAIT) })
		n = max(n, 0)
		_, _, ended := frames(append(stream[:len(stream):len(stream)], queued[:n]...))
		if n < peerBuffer && !ended {
			if time.Now().After(deadline) {
				t.Fatalf("the stream has neither filled the peer's buffer nor ended: %d bytes wait", n)
			}
			continue
		}
		end.Control(func(fd uintptr) { unix.Read(int(fd), queued[:n]) })
		if stream = append(stream, queued[:n]...); ended {
			carried, crossed, _ = frames(stream)
			return carried, crossed
		}
	}
}

func TestUploadsFramesEndWhereThePeersBufferEnds(t *testing.T) {
	node, port := nodeEnd(t)
	client := proxyPort(t, keyedForwarder(unix.VMADDR_CID_LOCAL, port))
	deadline := time.Now().Add(budget)
	up := carrying(t, node, deadline)
	defer up.Close()
	// Two writes, the second once the first is at the node: each read is then a known size, and no frame need cross.
	sent := make([]byte, 2*60000)
	rand.Read(sent)
	client.Write(sent[:60000])
	end, _ := up.SyscallConn()
	if err := end.Read(func(fd uintptr) bool {
		n, _, _ := unix.Recvfrom(int(fd), make([]byte, peerBuffer), unix.MSG_PEEK)
		return n >= keySize+4+60000
	}); err != nil {
		t.Fatalf("the first write did not reach the node: %v", err)
	}
	client.Write(sent[60000:])
	client.CloseWrite()
	carried, crossed := atNode(t, up, keySize, deadline)
	if !bytes.Equal(carried, sent) {
		t.Fatalf("the frames carry %d bytes: want the %d sent, unchanged", len(carried), len(sent))
	}
	if crossed > 0 {
		t.Fatalf("%d frames cross the end of the peer's buffer: each is sent in two packets", crossed)
	}
}

// gate is a reader that ends once it is closed: in a MultiReader it holds back the readers after it.
type gate chan struct{}

func (g gate) Read([]byte) (int, error) {
	<-g
	return 0, io.EOF
}

// crossings frames reads of these sizes onto a fitted connection and counts the frames that cross the peer buffer's end.
func crossings(t *testing.T, early bool, sizes ...int) int {
	t.Helper()
	node, port := nodeEnd(t)
	guest, err := vsockDial(unix.VMADDR_CID_LOCAL, port)
	if err != nil {
		t.Fatal(err)
	}
	defer guest.Close()
	deadline := time.Now().Add(budget)
	guest.SetWriteDeadline(deadline)
	taken := make(gate)
	var reads []io.Reader
	var sent []byte
	for i, size := range sizes {
		read := make([]byte, size)
		rand.Read(read)
		reads, sent = append(reads, bytes.NewReader(read)), append(sent, read...)
		if early && i == 0 {
			reads = append(reads, taken)
		}
	}
	written := make(chan error, 1)
	go func() { written <- toFrames(&fitted{File: guest}, io.MultiReader(reads...), nil) }()
	up := carrying(t, node, deadline)
	defer up.Close()
	var first []byte
	if early { // the node takes the first frame before its buffer is full, and the other reads wait for that
		first = make([]byte, 4+sizes[0])
		if _, err := io.ReadFull(up, first); err != nil {
			t.Fatal(err)
		}
		close(taken)
		first = first[4:]
	}
	carried, crossed := atNode(t, up, 0, deadline)
	select {
	case err := <-written:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Until(deadline)):
		t.Fatal("the writing did not end")
	}
	if carried = append(first, carried...); !bytes.Equal(carried, sent) {
		t.Fatalf("the frames carry %d bytes: want the %d sent, unchanged", len(carried), len(sent))
	}
	return crossed
}

func TestFrameAfterOneThatLeftNoRoomForAFrameStillEndsWhereThePeersBufferEnds(t *testing.T) {
	// A first frame that ends four bytes before the buffer does, then an upload: the frame sent four bytes short crosses.
	if crossed := crossings(t, false, peerBuffer-8, 4*maxFrame); crossed > 1 {
		t.Fatalf("%d frames cross the end of the peer's buffer: with under five bytes of room every full frame does", crossed)
	}
}

func TestFramesEndWhereThePeersBufferEndsAgainAfterItMadeRoomEarly(t *testing.T) {
	// As Firecracker does with under 4 KiB free: one frame then finds the buffer's end again.
	if crossed := crossings(t, true, peerBuffer-4000, 8*maxFrame); crossed > 1 {
		t.Fatalf("%d frames cross the end of the peer's buffer: a write cut short did not show where it ends", crossed)
	}
}
