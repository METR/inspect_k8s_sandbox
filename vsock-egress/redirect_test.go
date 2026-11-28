package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ownNamespace, in the environment, says this binary runs in a network namespace that is one test's own.
const ownNamespace = "VSOCK_EGRESS_TEST_OWN_NAMESPACE"

// namespaced is true in a network namespace of the test's own, with lo up as in a guest: redirect changes the one it runs in. Elsewhere it runs the test there, as a child, and is false.
func namespaced(t *testing.T) bool {
	t.Helper()
	if os.Getenv(ownNamespace) == "" {
		if os.Geteuid() != 0 {
			t.Skip("only root can make a network namespace")
		}
		there := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.v")
		there.Env = append(os.Environ(), ownNamespace+"=1")
		there.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNET}
		out, err := there.CombinedOutput()
		t.Logf("%s", out)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte("--- SKIP")) {
			t.Skip("it skipped there")
		}
		return false
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	lo, _ := unix.NewIfreq("lo") // down in a new namespace
	lo.SetUint16(unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, lo); err != nil {
		t.Fatal(err)
	}
	return true
}

// redirected is namespaced once redirect has run there.
func redirected(t *testing.T) bool {
	t.Helper()
	if !namespaced(t) {
		return false
	}
	if err := redirect(nil); err != nil {
		t.Fatalf("redirect: %v", err)
	}
	return true
}

func TestRedirectGivenAnArgumentChangesNothing(t *testing.T) {
	if !namespaced(t) {
		return
	}
	if err := redirect([]string{"help"}); err == nil {
		t.Fatal("redirect took an argument")
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		if own, err := netip.ParsePrefix(addr.String()); err == nil && ownRange.Contains(own.Addr()) {
			t.Fatalf("redirect, given an argument, gave this machine %v", addr)
		}
	}
}

func TestConnectionToASiblingsAddressOpensAStreamThatSaysWhereItWasGoing(t *testing.T) {
	if !redirected(t) {
		return
	}
	proxy, proxied := loopback(t)
	siblings, err := vsockListen(siblingPort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { siblings.f.Close() })
	f := keyedForwarder(unix.VMADDR_CID_LOCAL, proxied)
	l, err := listen(fmt.Sprintf("127.0.0.1:%d", forwarderPort), clientBuffer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go f.serve(l)
	// opened is what the stream that the node's vsock port takes next opens with, for a connection made to addr.
	opened := func(node *vsockListener, addr string, size int) []byte {
		streams := make(chan *os.File, 1)
		go func() {
			if up, _, err := node.accept(); err == nil {
				streams <- up
			}
		}()
		c, err := net.DialTimeout("tcp", addr, budget)
		if err != nil {
			t.Fatalf("a connection to %s: %v", addr, err)
		}
		t.Cleanup(func() { c.Close() })
		c.Write([]byte("request"))
		up := within(t, streams, "stream to the node for a connection to "+addr)
		t.Cleanup(func() { up.Close() })
		up.SetDeadline(time.Now().Add(budget))
		hello := make([]byte, size)
		if _, err := io.ReadFull(up, hello); err != nil {
			t.Fatalf("the stream for a connection to %s opened with %q, %v", addr, hello, err)
		}
		return hello
	}

	want := append(append(f.key[:], "\xc6\x12\x00\x02\x1f\x40"...), frame("request")...)
	if hello := opened(siblings, "198.18.0.2:8000", len(want)); !bytes.Equal(hello, want) {
		t.Fatalf("the stream opened with %q: want the key, then 198.18.0.2 and port 8000, then the request", hello)
	}
	// The rule makes the kernel answer where any connection was going: one made to the proxy's port is still the proxy's.
	want = append(f.key[:], frame("request")...)
	if hello := opened(proxy, l.Addr().String(), len(want)); !bytes.Equal(hello, want) {
		t.Fatalf("the proxy's stream opened with %q: want the key and then the request", hello)
	}
}

func TestDatagramToASiblingsAddressIsRefusedWhereItIsSent(t *testing.T) {
	if !redirected(t) {
		return
	}
	c, err := net.Dial("udp", "198.18.0.2:8000")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Nothing carries it, and the address is the sandbox's own: sent, a server of the task's on that port would take it as its sibling's.
	if _, err := c.Write([]byte("datagram")); !errors.Is(err, unix.EPERM) {
		t.Fatalf("a datagram to a sibling's address was sent with %v: want it refused", err)
	}
}

func TestSiblingsConnectionReachesAServerOnEveryAddressAfterTheKey(t *testing.T) {
	if !redirected(t) {
		return
	}
	arrivals, port := loopback(t)
	f := keyedForwarder(unix.VMADDR_CID_LOCAL, 0)
	go f.fromNode(arrivals, func(c *os.File) { go f.arrive(c) })
	_, everywhere := serverAt(t, "0.0.0.0:8000")
	serverAt(t, "127.0.0.1:8001")
	// The node's side of one sibling's connection: it reads the key, then names the port.
	arrive := func(named string) *os.File {
		c, err := vsockDial(unix.VMADDR_CID_LOCAL, port)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(budget))
		key := make([]byte, keySize)
		if _, err := io.ReadFull(c, key); err != nil || !bytes.Equal(key, f.key[:]) {
			t.Fatalf("the node read %q, %v: want the forwarder's key before it names a port", key, err)
		}
		c.Write(append([]byte(named), frame("request")...))
		return c
	}

	arrive("\x1f\x40") // port 8000
	got := within(t, everywhere, "connection to the server on every address")
	got.SetDeadline(time.Now().Add(budget))
	request := make([]byte, len("request"))
	if _, err := io.ReadFull(got, request); err != nil || string(request) != "request" {
		t.Fatalf("the server read %q, %v: want the request", request, err)
	}
	if at, from := got.LocalAddr().(*net.TCPAddr).IP.String(), got.RemoteAddr().(*net.TCPAddr).IP.String(); at != "198.19.0.1" || from != "198.19.0.2" {
		t.Fatalf("the server took its sibling's connection at %v from %v: want at 198.19.0.1 from 198.19.0.2, as the README says", at, from)
	}
	// The address the sandbox calls its own is no sibling's: a connection it makes there reaches its own server.
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if own, err := netip.ParsePrefix(addr.String()); err == nil && ownRange.Contains(own.Addr()) {
			c, err := net.DialTimeout("tcp", netip.AddrPortFrom(own.Addr(), 8000).String(), budget)
			if err != nil {
				t.Fatalf("a connection to %v, the sandbox's own address, did not reach its server: %v", own.Addr(), err)
			}
			defer c.Close()
			within(t, everywhere, "connection to the sandbox's own address")
		}
	}

	// As on a pod with a network card, where a sibling reaches no server that listens on 127.0.0.1 alone.
	if _, err := io.Copy(io.Discard, arrive("\x1f\x41")); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("a connection to port 8001 was neither delivered nor closed")
	}
}
