package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
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

// capturing is namespaced once capture has run there: it returns a forwarder for the sandbox, and where the test takes its streams, as the node.
func capturing(t *testing.T) (f *forwarder, node *vsockListener) {
	t.Helper()
	if !namespaced(t) {
		return nil, nil
	}
	node, port := loopback(t)
	f = keyedForwarder(unix.VMADDR_CID_LOCAL, port)
	const at = "127.0.0.1:3128" // where the chart's pods have the forwarder
	l, err := listen(at, clientBuffer)
	if err != nil {
		t.Fatal(err)
	}
	lookups, err := net.ListenPacket("udp", at)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close(); lookups.Close() })
	go f.serve(l)
	go f.names.serve(lookups)
	// As the chart's init container runs it, once the forwarder listens.
	if out, err := exec.Command(os.Args[0], "capture").CombinedOutput(); err != nil {
		t.Fatalf("capture: %v: %s", err, out)
	}
	return f, node
}

func TestCaptureFailsWhereTheForwarderGetsNothingOfWhatItRedirects(t *testing.T) {
	if !namespaced(t) {
		return
	}
	// No forwarder: to capture it is a kernel that took the rules and sends nothing where they say.
	if out, err := exec.Command(os.Args[0], "capture").CombinedOutput(); err == nil || !bytes.Contains(out, []byte("got no address from the forwarder")) {
		t.Fatalf("capture ended with %v and said %q: want it to fail, and the sandbox with it", err, out)
	}
}

// asked takes the next stream at node as the proxy, answers with reply, a frame for each part, and returns what the forwarder asked for.
func asked(t *testing.T, f *forwarder, node *vsockListener, reply ...string) chan string {
	requests := make(chan string, 1)
	go func() {
		up, _, err := node.accept()
		if err != nil {
			return
		}
		t.Cleanup(func() { up.Close() })
		up.SetDeadline(time.Now().Add(budget))
		opening := make([]byte, keySize+4)
		if _, err := io.ReadFull(up, opening); err != nil || !bytes.Equal(opening[:keySize], f.key[:]) {
			return
		}
		request := make([]byte, binary.BigEndian.Uint32(opening[keySize:]))
		if _, err := io.ReadFull(up, request); err != nil {
			return
		}
		for _, part := range reply {
			up.Write(frame(part))
		}
		requests <- string(request)
	}()
	return requests
}

func TestCapturedSandboxReachesANameAndAnAddressThroughItsProxy(t *testing.T) {
	f, node := capturing(t)
	if f == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	var found []string
	named, _ := f.names.address("example.com")
	// The forwarder answers a lookup sent to the sandbox's resolver, either way, and one sent to a resolver the sandbox named, at that name's address.
	for _, at := range [][2]string{{"udp", resolver.String()}, {"tcp", resolver.String()}, {"udp", named.String() + ":53"}} {
		asks := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, at[0], at[1])
		}}
		got, err := asks.LookupHost(ctx, "Example.com.") // with its dot: no search list of this machine's is tried first
		if err != nil || len(got) != 1 || !nameRange.Contains(netip.MustParseAddr(got[0])) || (found != nil && got[0] != found[0]) {
			t.Fatalf("example.com, asked of %v, resolved to %v, %v: want one address of %v each time, and none of IPv6", at, got, err, nameRange)
		}
		found = got
	}
	// A nat chain the guest adds later, at the priority of iptables' own, takes nothing capture redirects.
	guest := &nftables.Conn{}
	theirs := guest.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "guest"})
	guest.AddRule(&nftables.Rule{Table: theirs, Exprs: []expr.Any{&expr.Redir{}}, Chain: guest.AddChain(&nftables.Chain{
		Name: "output", Table: theirs, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest})})
	if err := guest.Flush(); err != nil {
		t.Fatal(err)
	}
	const answer, banner = "HTTP/1.1 200 OK\r\nserver: envoy\r\n\r\n", "SSH-2.0-origin\r\n"
	for target, as := range map[string]struct {
		want  string
		reply []string
	}{
		// The proxy's answer, then a server that speaks first: carried once the proxy has answered.
		found[0] + ":22": {"CONNECT example.com:22 HTTP/1.1\r\nHost: example.com:22\r\n\r\n", []string{answer, banner}},
		// The answer in two, the second a full frame: the rest of it is the server's.
		"203.0.113.9:443": {"CONNECT 203.0.113.9:443 HTTP/1.1\r\nHost: 203.0.113.9:443\r\n\r\n",
			[]string{answer[:9], answer[9:] + banner + strings.Repeat("x", maxFrame-len(answer[9:]+banner))}},
	} {
		requests := asked(t, f, node, as.reply...)
		c, err := net.DialTimeout("tcp", target, budget)
		if err != nil {
			t.Fatalf("a connection to %s: %v", target, err)
		}
		defer c.Close()
		if got := within(t, requests, "stream to the proxy for "+target); got != as.want {
			t.Fatalf("for a connection to %s the proxy was asked %q, want %q", target, got, as.want)
		}
		c.SetDeadline(time.Now().Add(budget))
		first := make([]byte, len(banner))
		if _, err := io.ReadFull(c, first); string(first) != banner {
			t.Fatalf("the client of %s read %q, %v: want what followed the proxy's answer, and none of the answer", target, first, err)
		}
	}
	// A program that knows of the proxy and comes to its port asks for itself: the forwarder adds no request of its own.
	const own = "CONNECT example.org:443 HTTP/1.1\r\n\r\n"
	requests := asked(t, f, node)
	c, err := net.DialTimeout("tcp", "127.0.0.1:3128", budget)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte(own))
	if got := within(t, requests, "stream to the proxy for a client of its own port"); got != own {
		t.Fatalf("for a client of the proxy's own port the proxy was asked %q, want what the client wrote, %q", got, own)
	}
}

func TestCapturedConnectionTheProxyRefusesIsReset(t *testing.T) {
	f, node := capturing(t)
	if f == nil {
		return
	}
	requests := asked(t, f, node, "HTTP/1.1 403 Forbidden\r\n\r\nHawk's egress proxy refused this request")
	read, err := reset(net.DialTimeout("tcp", "203.0.113.9:443", budget))
	within(t, requests, "stream to the proxy")
	if read != 0 || !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("the refused connection gave %d bytes and ended with %v: want a reset, and none of the proxy's answer", read, err)
	}
}

func TestCapturedSandboxSendsNothingButTCPAndLookups(t *testing.T) {
	f, node := capturing(t)
	if f == nil {
		return
	}
	streams := make(chan struct{}, 1)
	go func() {
		if _, _, err := node.accept(); err == nil {
			streams <- struct{}{}
		}
	}()
	named, _ := f.names.address("example.com")
	for _, to := range []string{"203.0.113.9:123", named.String() + ":123"} {
		c, err := net.Dial("udp", to)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Write([]byte("datagram")); !errors.Is(err, unix.EPERM) {
			t.Fatalf("a datagram to %s was sent with %v: want it refused where it is sent", to, err)
		}
	}
	// A resolver of the sandbox's own, at another of its addresses, still hears what is sent to it.
	own, err := net.ListenPacket("udp", "127.0.0.2:53")
	if err != nil {
		t.Fatal(err)
	}
	defer own.Close()
	asks, err := net.Dial("udp", own.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer asks.Close()
	asks.Write([]byte("question"))
	own.SetDeadline(time.Now().Add(budget))
	if size, _, err := own.ReadFrom(make([]byte, 16)); err != nil || size != len("question") {
		t.Fatalf("the sandbox's own resolver at %v read %d bytes, %v: want the question sent to it", own.LocalAddr(), size, err)
	}
	// A connection to the sandbox's own addresses is its own still: to its loopback, and where the forwarder hands in what comes for it.
	server, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	server.(*net.TCPListener).SetDeadline(time.Now().Add(budget))
	for _, at := range []netip.Addr{netip.MustParseAddr("127.0.0.1"), deliverTo} {
		to := netip.AddrPortFrom(at, uint16(server.Addr().(*net.TCPAddr).Port)).String()
		if c, err := net.DialTimeout("tcp", to, budget); err == nil {
			defer c.Close()
		}
		if _, err := server.Accept(); err != nil {
			t.Fatalf("a connection to the sandbox's own %s did not reach its server there: %v", to, err)
		}
	}
	// An address of the range that this forwarder gave no name.
	if _, err := reset(net.DialTimeout("tcp", "198.19.200.200:443", budget)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("a connection to an address no name was given ended with %v: want a reset", err)
	}
	select { // a stream would be there by now: the forwarder opens it before it resets a client the proxy did not answer for
	case <-streams:
		t.Fatal("the proxy was asked for an address that stands for no name")
	default:
	}
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
	forwardingWith(t) // as the chart's pods run it: with no address
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
