package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const budget = 30 * time.Second // bounds a hang; a passing test never waits for it

func TestPacerMakesUpForASleepThatRanLate(t *testing.T) {
	start := time.Unix(0, 0)
	clock := start
	const rate, late = 1 << 20, 5 * time.Millisecond
	p := &pacer{rate: rate, now: func() time.Time { return clock }, sleep: func(d time.Duration) { clock = clock.Add(d + late) }}
	for range 160 { // 10 MiB
		p.wait(64 << 10)
	}
	if took := clock.Sub(start); took > 10*time.Second+paceSlack {
		t.Fatalf("10 MiB at 1 MiB a second took %v on a clock whose sleeps run %v late: each late wake was paid for again", took, late)
	}
}

// pair returns the two ends of a new connection, closed when the test ends.
func pair(t *testing.T, network, address string) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	near, err := net.Dial(network, l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	far, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []net.Conn{near, far} {
		c.SetDeadline(time.Now().Add(budget))
		t.Cleanup(func() { c.Close() })
	}
	return near, far
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	near, far := pair(t, "tcp", "127.0.0.1:0")
	return near.(*net.TCPConn), far.(*net.TCPConn)
}

// vsockPair stands in for the vsock connection between a forwarder and its worker.
func vsockPair(t *testing.T) (net.Conn, net.Conn) {
	return pair(t, "unix", filepath.Join(t.TempDir(), "vsock"))
}

func frame(payload string) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(payload))), payload...)
}

func TestHalfClosedClientGetsItsReply(t *testing.T) {
	client, inSandbox := tcpPair(t)
	onNode, proxy := tcpPair(t)
	guest, node := vsockPair(t)
	go join(guest, inSandbox, nil, 0)
	go join(node, onNode, nil, 0)

	client.Write([]byte("request"))
	client.CloseWrite()
	if got, err := io.ReadAll(proxy); string(got) != "request" || err != nil {
		t.Fatalf("the proxy read %q, %v: want the request and then its end", got, err)
	}
	proxy.Write([]byte("reply"))
	proxy.Close()
	if got, err := io.ReadAll(client); string(got) != "reply" || err != nil {
		t.Fatalf("the client read %q, %v: want the reply and then a clean end", got, err)
	}
}

func TestBytesReadAreAcknowledgedAtOnce(t *testing.T) {
	client, inSandbox := tcpPair(t)
	onNode, proxy := tcpPair(t)
	guest, node := vsockPair(t)
	go join(guest, inSandbox, nil, 0)
	go join(node, onNode, nil, 0)
	raw, err := inSandbox.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	one, quick := make([]byte, 1), 0

	// A request, then acknowledgements held back, as the kernel holds them once replies flow, and a second request.
	for i, step := range []func([]byte) (int, error){client.Write, proxy.Read, client.Write, proxy.Read} {
		if i == 2 {
			if controlled := raw.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK, 0)
			}); controlled != nil || err != nil {
				t.Fatal(controlled, err)
			}
		}
		if _, err := step(one); err != nil {
			t.Fatal(err)
		}
	}
	// Whether the kernel acknowledges what the sandbox's side receives at once, or holds that back for a reply to carry.
	if controlled := raw.Control(func(fd uintptr) {
		quick, err = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK)
	}); controlled != nil || err != nil {
		t.Fatal(controlled, err)
	}

	if quick != 1 {
		t.Fatal("the connection still holds its acknowledgements back after a read: a client without TCP_NODELAY waits 40 ms for each before its next small write")
	}
}

func TestStreamCutShortIsNotACleanEnd(t *testing.T) {
	client, inSandbox := tcpPair(t)
	guest, node := vsockPair(t)
	go join(guest, inSandbox, nil, 0)

	node.Write(frame("half a body"))
	node.Close() // the worker died: no empty frame
	got, err := io.ReadAll(client)
	if err == nil {
		t.Fatalf("the client read %q and a clean end: a cut download would pass for a whole one", got)
	}
}

func TestProxyThatResetsWhileAWriteToItWaitsIsNoCleanEnd(t *testing.T) {
	for range 5 { // the kernel gives the reset to the waiting write or to the read: it was the write 19 times in 20
		onNode, proxy := tcpPair(t)
		guest, node := vsockPair(t)
		go join(node, onNode, nil, 0)

		go toFrames(guest, zeros{}, nil) // an upload the proxy never reads: its writes wait once the buffers are full
		time.Sleep(200 * time.Millisecond)
		proxy.SetLinger(0)
		proxy.Close()
		guest.SetReadDeadline(time.Now().Add(5 * time.Second))
		if got, err := io.ReadAll(guest); len(got) != 0 || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("the guest read %q, %v: want the stream cut short, with no frame", got, err)
		}
	}
}

func TestResetThatFollowsThePeersOwnEndLeavesItsReplyWhole(t *testing.T) {
	onNode, proxy := tcpPair(t)
	proxy.Write([]byte("reply"))
	proxy.Close()
	time.Sleep(50 * time.Millisecond)
	onNode.Write([]byte("more of the upload")) // the proxy has closed, and resets
	time.Sleep(50 * time.Millisecond)
	if got, err := io.ReadAll(unreset{onNode, new(atomic.Bool)}); string(got) != "reply" || err != nil {
		t.Fatalf("the node read %q, %v: want the reply and then a clean end", got, err)
	}
}

func TestPeerThatGoesAwayAfterItsLastFrameEndsTheStream(t *testing.T) {
	onNode, proxy := tcpPair(t)
	guest, node := vsockPair(t)
	ended := make(chan struct{})
	go func() {
		join(node, onNode, nil, 0)
		close(ended)
	}()

	guest.Write([]byte{0, 0, 0, 0}) // the guest's side has ended
	if got, err := io.ReadAll(proxy); len(got) != 0 || err != nil {
		t.Fatalf("the proxy read %q, %v: want the end of the request", got, err)
	}
	guest.Close() // and now the guest has gone, while the proxy says nothing
	select {
	case <-ended:
	case <-time.After(budget):
		t.Fatal("the stream outlived its vsock connection: it would hold its slot until the proxy gave up")
	}
}
