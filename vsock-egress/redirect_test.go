package main

import (
	"bytes"
	"context"
	"errors"
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

// redirected is namespaced once redirect has run there, twice: the kubelet may run an init container again.
func redirected(t *testing.T) bool {
	t.Helper()
	if !namespaced(t) {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	for range 2 {
		if out, err := exec.CommandContext(ctx, os.Args[0], "redirect").CombinedOutput(); err != nil { // as the chart's init container runs it
			t.Fatalf("redirect: %v: %s", err, out)
		}
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
	l, err := listen("127.0.0.1:3128", clientBuffer)
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
	// A ping too, which the sandbox's own kernel would else answer as the sibling.
	ping, err := net.Dial("ip4:icmp", "198.18.0.2")
	if err != nil {
		t.Fatal(err)
	}
	defer ping.Close()
	if _, err := ping.Write([]byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0}); !errors.Is(err, unix.EPERM) { // an echo request
		t.Fatalf("a ping to a sibling's address was sent with %v: want it refused", err)
	}
	// And nothing of what the sandbox sends itself.
	own, err := net.Dial("udp", "127.0.0.1:8000")
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	if _, err := own.Write([]byte("datagram")); err != nil {
		t.Fatalf("a datagram to the sandbox's own loopback: %v", err)
	}
}

func TestForwardGivenNoAddressListensWhereNoSiblingIsDelivered(t *testing.T) {
	if !redirected(t) {
		return
	}
	loopback(t) // skips where this machine has no vsock to itself
	file, said := t.TempDir()+"/key", new(bytes.Buffer)
	forwarder := exec.Command(os.Args[0], "forward", "-key", file) // as the chart's pods run it
	forwarder.Stderr = said
	if err := forwarder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		forwarder.Process.Kill()
		forwarder.Wait()
	})
	for deadline := time.Now().Add(budget); ; time.Sleep(time.Millisecond) {
		if _, err := os.Stat(file + readySuffix); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("forward did not come to listen: %s", said)
		}
	}
	// A sibling's connection is delivered at 198.19.0.1: the proxy's port there would open it the pod's own stream to its proxy.
	if c, err := net.DialTimeout("tcp", "198.19.0.1:3128", budget); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("a connection to the forwarder's port at the address siblings are delivered to gave %v, %v: want it refused", c, err)
	}
	c, err := net.DialTimeout("tcp", "127.0.0.1:3128", budget)
	if err != nil {
		t.Fatalf("the sandbox's own programs do not reach the forwarder: %v", err)
	}
	c.Close()
}

func TestSiblingsConnectionReachesAServerOnEveryAddressAfterTheKey(t *testing.T) {
	if !redirected(t) {
		return
	}
	loopback(t) // skips where this machine has no vsock to itself
	// The forwarder as forward starts it, but for the node's CID: this test's own, so that it is the node.
	f, file := newForwarder(unix.VMADDR_CID_LOCAL, 0), t.TempDir()+"/key"
	ended := make(chan error, 1)
	go func() { ended <- f.run("127.0.0.1:3128", file) }()
	for deadline := time.Now().Add(budget); ; time.Sleep(time.Millisecond) {
		if _, err := os.Stat(file + readySuffix); err == nil {
			break
		}
		select {
		case err := <-ended:
			t.Fatalf("the forwarder ended: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the forwarder did not come to listen")
		}
	}
	// Its key, as the node fetches it.
	keys, err := vsockDial(unix.VMADDR_CID_LOCAL, keyPort)
	if err != nil {
		t.Fatal(err)
	}
	defer keys.Close()
	keys.SetDeadline(time.Now().Add(budget))
	minted := make([]byte, keySize)
	if _, err := io.ReadFull(keys, minted); err != nil || bytes.Equal(minted, make([]byte, keySize)) {
		t.Fatalf("the node fetched the key %x, %v: want the one the forwarder minted", minted, err)
	}
	_, everywhere := serverAt(t, "0.0.0.0:8000")
	serverAt(t, "127.0.0.1:8001")
	_, second := serverAt(t, "0.0.0.0:8002")
	// One port to connect from: taken as the forwarder binds, it would be closed to the second connection below, and to the sandbox's own.
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_local_port_range", []byte("40000 40000"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The node's side of one sibling's connection: it reads the key, then names the port.
	arrive := func(named string) *os.File {
		c, err := vsockDial(unix.VMADDR_CID_LOCAL, inboundPort)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(budget))
		key := make([]byte, keySize)
		if _, err := io.ReadFull(c, key); err != nil || !bytes.Equal(key, minted) {
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
	arrive("\x1f\x42") // port 8002, while the first is open
	within(t, second, "connection from a second sibling")
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
