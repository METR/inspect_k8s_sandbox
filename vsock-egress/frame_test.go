package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"
)

const budget = 30 * time.Second // bounds a hang; a passing test never waits for it

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
	go join(guest, inSandbox, nil)
	go join(node, onNode, nil)

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

func TestStreamCutShortIsNotACleanEnd(t *testing.T) {
	client, inSandbox := tcpPair(t)
	guest, node := vsockPair(t)
	go join(guest, inSandbox, nil)

	node.Write(frame("half a body"))
	node.Close() // the worker died: no empty frame
	got, err := io.ReadAll(client)
	if err == nil {
		t.Fatalf("the client read %q and a clean end: a cut download would pass for a whole one", got)
	}
}

func TestFrameLongerThanTheBoundIsRefused(t *testing.T) {
	long := binary.BigEndian.AppendUint32(nil, maxFrame+1)
	if err := fromFrames(io.Discard, bytes.NewReader(long), nil); !errors.Is(err, errFrame) {
		t.Fatalf("got %v, want %v", err, errFrame)
	}
}
