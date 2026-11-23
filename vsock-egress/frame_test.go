package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
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
	return pairBy(t, network, address, net.Dialer{})
}

func pairBy(t *testing.T, network, address string, d net.Dialer) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	near, err := d.Dial(network, l.Addr().String())
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

// unreadPair is a tcpPair whose near end holds little that it has not read, from its first packet on: most of what the far end writes stays unsent.
func unreadPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	near, far := pairBy(t, "tcp", "127.0.0.1:0", net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, 4<<10) })
	}})
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
	read := unreset{inSandbox, new(atomic.Bool)}
	raw, err := inSandbox.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	// Whether the kernel acknowledges what this side receives at once, or holds that back for a reply to carry.
	atOnce := func() (quick int) {
		if controlled := raw.Control(func(fd uintptr) {
			quick, err = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_QUICKACK)
		}); controlled != nil || err != nil {
			t.Fatal(controlled, err)
		}
		return quick
	}
	one := make([]byte, 1)
	// Requests and their replies, as through a proxy: the kernel then holds acknowledgements back. The first is read as the last will be: asking once a connection would not do.
	receive := read.Read
	for range 8 {
		for _, step := range []func([]byte) (int, error){client.Write, receive, inSandbox.Write, client.Read} {
			if _, err := step(one); err != nil {
				t.Fatal(err)
			}
		}
		receive = inSandbox.Read
	}
	if atOnce() != 0 {
		t.Skip("this kernel holds no acknowledgement back here, so a read has nothing to change")
	}
	sent := time.Now()

	if _, err := client.Write(one); err != nil {
		t.Fatal(err)
	}
	// Into the room a stream's reads have, more than the peer fills.
	if _, err := read.Read(make([]byte, maxFrame)); err != nil {
		t.Fatal(err)
	}

	if atOnce() != 1 {
		t.Fatal("the connection still holds its acknowledgements back after a read: a client without TCP_NODELAY waits 40 ms for each before its next small write")
	}
	if time.Since(sent) > 20*time.Millisecond {
		t.Skip("too slow to tell: 40 ms after bytes arrive the kernel acknowledges them whatever was asked")
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

func TestReplyItsClientNeverTakesIsResetAtTheBound(t *testing.T) {
	client, inSandbox := unreadPair(t)
	guest, node := vsockPair(t)
	ended := make(chan struct{})
	go func() {
		join(guest, inSandbox, nil, 100*time.Millisecond)
		close(ended)
	}()
	client.CloseWrite()
	if err := toFrames(node, strings.NewReader(strings.Repeat("r", 100<<10)), nil); err != nil { // all of it fits the socket's buffer: the stream ends cleanly
		t.Fatal(err)
	}

	within(t, ended, "end of a stream whose client took none of its reply")
	if got, err := io.ReadAll(client); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("the client read %d bytes, %v, once the stream had gone: want a reset, for closed with a reply unsent the kernel keeps the socket", len(got), err)
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
