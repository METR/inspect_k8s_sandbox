package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
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
		t.Logf("%s", out) // a test that skips there is named here
		if err != nil {
			t.Fatal(err)
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

func TestRedirectAskedForHelpChangesNothing(t *testing.T) {
	if !namespaced(t) {
		return
	}
	// As an operator might ask on a node, as root: the address redirect adds would make 198.18.0.0/15 that machine's own.
	out, err := exec.Command(os.Args[0], "redirect", "-h").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "Usage of redirect") {
		t.Fatalf("redirect -h ended with %v: %s: want its usage alone", err, out)
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range addrs {
		if addr.String() == ownRange.String() {
			t.Fatalf("redirect -h gave this machine %v", addr)
		}
	}
}

func TestConnectionToASiblingsAddressOpensAStreamThatSaysWhereItWasGoing(t *testing.T) {
	if !redirected(t) {
		return
	}
	proxy, proxied := loopback(t)
	siblings, port := loopback(t)
	f := keyedForwarder(unix.VMADDR_CID_LOCAL, proxied)
	f.siblings = port
	l, err := listen(fmt.Sprintf("127.0.0.1:%d", forwarderPort), clientBuffer)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go f.serve(l)
	// A server of the task's on that sibling's port, on every address: redirect must not leave the connection to it.
	_, own := serverAt(t, "0.0.0.0:8000")
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
	select {
	case <-own:
		t.Fatal("the connection reached the sandbox's own server on that port")
	default:
	}
	// The rule makes the kernel answer where any connection was going: one made to the proxy's port is still the proxy's.
	want = append(f.key[:], frame("request")...)
	if hello := opened(proxy, l.Addr().String(), len(want)); !bytes.Equal(hello, want) {
		t.Fatalf("the proxy's stream opened with %q: want the key and then the request", hello)
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
	_, alone := serverAt(t, "127.0.0.1:8001")
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
	if from := got.RemoteAddr().(*net.TCPAddr).IP; from.IsLoopback() {
		t.Fatalf("the server sees its sibling at %v, as a program of its own machine", from)
	}

	// As on a pod with a network card, where a sibling reaches no server that listens on 127.0.0.1 alone.
	if _, err := io.Copy(io.Discard, arrive("\x1f\x41")); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("a connection to port 8001 was neither delivered nor closed")
	}
	select {
	case <-alone:
		t.Fatal("a sibling's connection reached a server on 127.0.0.1 alone")
	default:
	}
}
