package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
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
	f := newForwarder(hostCID, streamPort)
	f.connect = func(uint32, uint32) (*os.File, error) { return os.CreateTemp(t.TempDir(), "") } // its worker listens
	if err := f.ready(file); err == nil {
		t.Fatal("ready passed for a forwarder that does not listen")
	}
}

func TestSecondForwarderLeavesTheFirstReady(t *testing.T) {
	if first, err := vsockListen(keyPort); err == nil { // the forwarder at work holds this port, which one alone can; where the test cannot take it, nor can a second
		defer first.f.Close()
	}
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file+readySuffix, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	err := forward([]string{"-listen", "127.0.0.1:65536", "-key", file}) // a proxy port it cannot take: it ends, refused or not

	if _, gone := os.Stat(file + readySuffix); gone != nil {
		t.Fatalf("a second forwarder ended with %v, and the first one's ready file gave %v: want the file left", err, gone)
	}
	if _, kept := os.Stat(file); kept == nil {
		t.Fatalf("a second forwarder ended with %v, and wrote a key file, which only the one that holds the port may", err)
	}
}

func TestForwarderWhoseWorkerDoesNotListenIsNotReady(t *testing.T) {
	node, port := loopback(t)
	f := newForwarder(unix.VMADDR_CID_LOCAL, port)
	file := filepath.Join(t.TempDir(), "key")
	if err := errors.Join(f.loadKey(file), os.WriteFile(file+readySuffix, nil, 0o600)); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan *os.File, 1)
	go func() {
		c, _, _ := node.accept()
		accepted <- c
	}()
	if err := f.ready(file); err != nil {
		t.Fatalf("ready failed with a worker listening: %v", err)
	}
	probe := within(t, accepted, "stream from the probe")
	probe.SetDeadline(time.Now().Add(budget))
	if sent, err := io.ReadAll(probe); err != nil || !bytes.Equal(sent, f.key[:]) {
		t.Fatalf("the node read %d bytes, %v: want the key and then the stream's end, which every worker takes", len(sent), err)
	}
	probe.Close()
	node.f.Close()
	if err := f.ready(file); err == nil {
		t.Fatal("ready passed with no worker listening: the sandbox would be handed over with no way out")
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
	go f.serve(l)
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

func TestStreamCapsItsClientSocketOnlyOnceItHasAPlace(t *testing.T) {
	_, placed := tcpPair(t)
	l, err := listen("127.0.0.1:0", clientBuffer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	waiting, err := l.Accept() // as the forwarder's listener hands a connection over
	if err != nil {
		t.Fatal(err)
	}
	kept, err := waiting.(*net.TCPConn).File() // the socket, past the stream's close of it
	if err != nil {
		t.Fatal(err)
	}
	defer kept.Close()
	f := newForwarder(0, 0)
	f.wait = budget // a stalled runner must not time out the stream that has a place free
	var held [2]int
	f.connect = func(uint32, uint32) (*os.File, error) { // a stream dials the node once it has its place and its caps
		held = buffers(t, placed)
		return nil, errors.New("the test has seen the socket")
	}

	f.stream(placed)
	for range maxStreams { // every place is taken
		f.slots <- struct{}{}
	}
	f.wait = 0
	f.stream(waiting.(*net.TCPConn))

	if want := capped(t, 128<<10); held != want { // the size itself: a change to it must be measured against the forwarder's memory limit in the chart
		t.Errorf("a stream's socket to its client holds %v bytes each way: want %v, the kernel's count of the cap", held, want)
	}
	locked, err := unix.GetsockoptInt(int(kept.Fd()), unix.SOL_SOCKET, unix.SO_BUF_LOCK)
	if got, want := buffers(t, kept)[0], capped(t, 64<<10)[0]; err != nil || got != want || locked&unix.SOCK_RCVBUF_LOCK == 0 {
		t.Errorf("a connection that got no place takes %d bytes from its client, with buffers locked as %d (%v): want %d, half the cap, locked, as its listener gave it: unlocked, small segments grow it before the forwarder has seen it", got, locked, err, want)
	}
}

// forwarding starts the program's own forward, in a process of its own, and returns its TCP address and its key's file once it listens: what a sandbox and its node meet is whatever that makes.
func forwarding(t *testing.T) (addr, file string) {
	t.Helper()
	loopback(t) // skips where this machine has no vsock to itself: after that, a forward that ends is a failure
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr, file = free.Addr().String(), filepath.Join(t.TempDir(), "key")
	free.Close()
	forwarder := exec.Command(os.Args[0], "forward", "-listen", addr, "-key", file)
	said := new(strings.Builder)
	forwarder.Stderr = said
	if err := forwarder.Start(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- forwarder.Wait() }()
	t.Cleanup(func() {
		forwarder.Process.Kill()
		<-ended
	})
	for deadline := time.Now().Add(budget); ; time.Sleep(time.Millisecond) {
		if _, err := os.Stat(file + readySuffix); err == nil {
			return addr, file
		}
		select {
		case err := <-ended:
			ended <- err
			t.Fatalf("forward did not come to listen: %v: %s", err, said)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("forward neither listened nor ended")
		}
	}
}

func TestForwardTakesItsSiblingsConnectionsFromTheNodeAlone(t *testing.T) {
	forwarding(t)
	// This test is a process of the forwarder's own VM, as a task's would be: only the node may hand it a sibling's connection.
	c, err := vsockDial(unix.VMADDR_CID_LOCAL, inboundPort)
	if err != nil {
		t.Fatalf("forward does not listen for its siblings' connections: %v", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(budget))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("a process of the VM read %d bytes, %v, at the port for siblings' connections: want it closed with no key", n, err)
	}
}

func TestForwardAnswersLookupsAtItsProxyPort(t *testing.T) {
	addr, key := forwarding(t)
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	asks := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", addr)
	}}
	if got, err := asks.LookupHost(ctx, "example.com"); err != nil || len(got) != 1 || !nameRange.Contains(netip.MustParseAddr(got[0])) {
		t.Fatalf("example.com, asked of forward at %v, resolved to %v, %v: want one address of %v", addr, got, err, nameRange)
	}
	// Beside the key, which outlives the forwarder: one started again finds there how many addresses were given.
	if _, err := os.Stat(key + ".names"); err != nil {
		t.Fatalf("forward kept no count of the addresses it gave: %v", err)
	}
}

func TestClientThatAsksForMultipathTCPGetsPlainTCP(t *testing.T) {
	if on, _ := os.ReadFile("/proc/sys/net/mptcp/enabled"); strings.TrimSpace(string(on)) != "1" {
		t.Skip("this kernel has multipath TCP off")
	}
	addr, _ := forwarding(t)
	var guest net.Dialer
	guest.SetMultipathTCP(true)
	client, err := guest.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if multipath, err := client.(*net.TCPConn).MultipathTCP(); multipath || err != nil {
		t.Fatalf("a client that asked the forwarder for multipath TCP got it: %v (%v): want plain TCP, the only kind whose buffers the forwarder's bounds hold", multipath, err)
	}
}

func TestStreamWhoseClientHasNotTakenItsReplyKeepsItsPlace(t *testing.T) {
	client, inSandbox := unreadPair(t)
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	guest, node := os.NewFile(uintptr(pair[0]), "vsock"), os.NewFile(uintptr(pair[1]), "node")
	defer node.Close()
	f := keyedForwarder(0, 0)
	f.connect = func(uint32, uint32) (*os.File, error) { return guest, nil }
	ended := make(chan struct{})
	go func() {
		f.stream(inSandbox)
		close(ended)
	}()
	reply := strings.Repeat("r", 100<<10) // all of it fits the socket's buffer: the stream ends cleanly with most of it unsent
	client.CloseWrite()
	if err := toFrames(node, strings.NewReader(reply), nil); err != nil {
		t.Fatal(err)
	}

	node.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) // a wait for nothing: a stalled runner can hide a stream that ends early, and fails none that does not
	if _, err := io.Copy(io.Discard, node); !errors.Is(err, os.ErrDeadlineExceeded) || len(f.slots) != 1 {
		t.Fatalf("the stream ended (%v, %d places taken) with its reply not yet taken: want it to keep its place, for the kernel holds what is unsent", err, len(f.slots))
	}
	if got, err := io.ReadAll(client); string(got) != reply || err != nil {
		t.Fatalf("the client read %d bytes, %v: want the whole reply of %d and then a clean end", len(got), err, len(reply))
	}
	within(t, ended, "end of a stream whose client has taken its reply")
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

func TestCommandsForTheSandboxTakeOnlyTheseFlags(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second) // a command that started instead would serve until killed
	defer cancel()
	// The README tells an operator that none of these takes a vsock port or address from its caller: a flag is one its caller sets.
	for command, want := range map[string]string{"forward": "-key -listen", "ready": "-key", "canary": ""} {
		out, err := exec.CommandContext(ctx, os.Args[0], command, "-h").CombinedOutput()
		var flags []string
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "  -") {
				flags = append(flags, strings.Fields(line)[0])
			}
		}
		if got := strings.Join(flags, " "); err != nil || got != want {
			t.Errorf("%s takes %q (%v): want %q alone", command, got, err, want)
		}
	}
}
