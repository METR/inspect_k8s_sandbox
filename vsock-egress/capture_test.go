package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

func loadedNames(t *testing.T, file string, own ...string) *names {
	t.Helper()
	n, err := loadNames(file, own)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.kept.Close() })
	return n
}

func TestNameKeepsItsAddressWhenTheForwarderIsRestarted(t *testing.T) {
	file := filepath.Join(t.TempDir(), "names")
	first := loadedNames(t, file)
	given := map[string]netip.Addr{}
	for _, name := range []string{"pypi.org", "files.pythonhosted.org", "pypi.org"} {
		addr, ok := first.address(name)
		if !ok || !captureRange.Contains(addr) {
			t.Fatalf("%s got %v, %v: want an address in %v", name, addr, ok, captureRange)
		}
		if had, again := given[name]; again && had != addr {
			t.Fatalf("%s got %v and then %v", name, had, addr)
		}
		given[name] = addr
	}
	if given["pypi.org"] == given["files.pythonhosted.org"] {
		t.Fatalf("two names share %v", given["pypi.org"])
	}

	restarted := loadedNames(t, file)
	for name, addr := range given {
		if got, ok := restarted.name(addr); !ok || got != name {
			t.Fatalf("after a restart %v is %q, %v: a program that kept it wants %q", addr, got, ok, name)
		}
		if got, _ := restarted.address(name); got != addr {
			t.Fatalf("after a restart %s got %v, want %v again", name, got, addr)
		}
	}
	for _, addr := range []netip.Addr{captureRange.Addr(), given["files.pythonhosted.org"].Next(), netip.MustParseAddr("127.0.0.1")} {
		if name, ok := restarted.name(addr); ok {
			t.Fatalf("%v, which no name was given, is %q", addr, name)
		}
	}
}

// asked sends n one question as a resolver does and returns the reply's header and answers.
func asked(t *testing.T, n *names, name string, kind dnsmessage.Type) (dnsmessage.Header, []dnsmessage.Resource) {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
	b.StartQuestions()
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	query, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	h, err := p.Start(n.answer(query))
	if err != nil {
		t.Fatalf("the reply to %s: %v", name, err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		t.Fatal(err)
	}
	return h, answers
}

func TestLookupGetsTheNamesAddressAndNoIPv6(t *testing.T) {
	n := loadedNames(t, filepath.Join(t.TempDir(), "names"))
	queries, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { queries.Close() })
	go n.resolve(queries)
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, "udp4", queries.LocalAddr().String())
	}}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	got, err := resolver.LookupNetIP(ctx, "ip", "PyPI.org") // IPv4 and IPv6, as getaddrinfo asks
	want, _ := n.address("pypi.org")
	if err != nil || len(got) != 1 || got[0] != want {
		t.Fatalf("the lookup got %v, %v: want %v alone", got, err, want)
	}
	// musl fails a whole lookup if either of its two questions gets an error.
	if h, answers := asked(t, n, "pypi.org.", dnsmessage.TypeAAAA); h.RCode != dnsmessage.RCodeSuccess || len(answers) != 0 {
		t.Fatalf("the question for IPv6 got %v and %d answers: want success and none", h.RCode, len(answers))
	}
}

func TestLookupOfThePodsOwnNameLeadsToThePod(t *testing.T) {
	n := loadedNames(t, filepath.Join(t.TempDir(), "names"), "default", "agent-env-x-default")
	for _, name := range []string{"default.", "Agent-Env-X-Default."} {
		h, answers := asked(t, n, name, dnsmessage.TypeA)
		if h.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 || answers[0].Body.(*dnsmessage.AResource).A != [4]byte{127, 0, 0, 1} {
			t.Fatalf("%s got %v and %v: want 127.0.0.1", name, h.RCode, answers)
		}
	}
	if len(n.list) != 0 {
		t.Fatalf("%v were given addresses that lead to the proxy", n.list)
	}
}

func TestLookupThatCannotBeKeptGetsNoAddress(t *testing.T) {
	n := loadedNames(t, filepath.Join(t.TempDir(), "names"))
	if h, answers := asked(t, n, "evil\r\nHost: other.example.", dnsmessage.TypeA); h.RCode != dnsmessage.RCodeServerFailure || len(answers) != 0 || len(n.list) != 0 {
		t.Fatalf("a name that is no host name got %v, %d answers, and %d names are kept", h.RCode, len(answers), len(n.list))
	}
	for i := range maxNames {
		if _, ok := n.address(fmt.Sprintf("host-%d.example", i)); !ok {
			t.Fatalf("name %d of %d got no address", i+1, maxNames)
		}
	}
	if h, answers := asked(t, n, "one-more.example.", dnsmessage.TypeA); h.RCode != dnsmessage.RCodeServerFailure || len(answers) != 0 {
		t.Fatalf("name %d got %v and %d answers", maxNames+1, h.RCode, len(answers))
	}
	if h, answers := asked(t, n, "host-0.example.", dnsmessage.TypeA); h.RCode != dnsmessage.RCodeSuccess || len(answers) != 1 {
		t.Fatalf("a name that has its address got %v and %d answers", h.RCode, len(answers))
	}
}

func TestCapturedConnectionAsksTheProxyForItsName(t *testing.T) {
	target, accepted := proxy(t)
	f := keyedForwarder(0, 0)
	viaUnix(t, f, newWorker(firecracker(t, map[uint32]string{keyPort: string(f.key[:])}), target, 0))
	f.names = loadedNames(t, filepath.Join(t.TempDir(), "names"))
	pypi, _ := f.names.address("pypi.org")
	going := make(chan netip.AddrPort, 1) // where the next connection was going, or nowhere the kernel knows of
	f.original = func(*net.TCPConn) (to netip.AddrPort, err error) {
		if to = <-going; !to.IsValid() {
			err = unix.ENOENT
		}
		return to, err
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go f.serve(l, f.captured)
	// redirected is a program's connection to an address, and the first thing it reads there.
	redirected := func(to netip.AddrPort, read []byte) (net.Conn, int, error) {
		going <- to
		c, err := net.Dial("tcp", l.Addr().String())
		if err != nil { // a connection the forwarder resets at once may learn of it here
			return nil, 0, err
		}
		t.Cleanup(func() { c.Close() })
		c.SetDeadline(time.Now().Add(budget))
		if read == nil {
			return c, 0, nil
		}
		n, err := c.Read(read)
		return c, n, err
	}
	asks := func() (net.Conn, *bufio.Reader) {
		select {
		case c := <-accepted:
			c.SetDeadline(time.Now().Add(budget))
			r := bufio.NewReader(c)
			if request, err := http.ReadRequest(r); err != nil || request.Method != "CONNECT" || request.Host != "pypi.org:8443" {
				t.Fatalf("the proxy read %+v, %v: want CONNECT pypi.org:8443", request, err)
			}
			return c, r
		case <-time.After(budget):
			t.Fatal("the connection did not reach the proxy")
			return nil, nil
		}
	}

	client, _, err := redirected(netip.AddrPortFrom(pypi, 8443), nil)
	if err != nil {
		t.Fatal(err)
	}
	atProxy, fromClient := asks()
	atProxy.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\nhello")) // a server that speaks first
	client.Write([]byte("ping"))
	got := make([]byte, 5)
	if _, err := io.ReadFull(client, got); string(got) != "hello" {
		t.Fatalf("the program read %q, %v: want what follows the proxy's reply", got, err)
	}
	if _, err := io.ReadFull(fromClient, got[:4]); string(got[:4]) != "ping" {
		t.Fatalf("the proxy read %q, %v inside the tunnel", got[:4], err)
	}

	if client, _, err = redirected(netip.AddrPortFrom(pypi, 8443), nil); err != nil {
		t.Fatal(err)
	}
	atProxy, _ = asks()
	atProxy.Write([]byte("HTTP/1.1 403 Forbidden\r\ncontent-length: 2\r\n\r\nno"))
	if n, err := client.Read(got); n != 0 || !errors.Is(err, unix.ECONNRESET) {
		t.Fatalf("the program read %q, %v from a connection the proxy refused: want a reset", got[:n], err)
	}

	for name, dst := range map[string]netip.AddrPort{
		"an address no name was given":    netip.AddrPortFrom(pypi.Next(), 443),
		"a connection nothing redirected": netip.MustParseAddrPort("127.0.0.1:3127"),
		"no original destination":         {},
	} {
		if _, n, err := redirected(dst, got); n != 0 || !errors.Is(err, unix.ECONNRESET) {
			t.Fatalf("%s: the program read %q, %v: want a reset", name, got[:n], err)
		}
		if len(accepted) != 0 {
			t.Fatalf("%s: the connection reached the proxy", name)
		}
	}
}

func TestForwarderWithoutItsCapturePortIsNotReady(t *testing.T) {
	taken, err := net.Listen("tcp4", captureAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	file := filepath.Join(t.TempDir(), "key")
	failed := make(chan error, 1)
	go func() { failed <- forward([]string{"-listen", "127.0.0.1:0", "-key", file, "-capture"}) }()
	for deadline := time.Now().Add(budget); ; time.Sleep(10 * time.Millisecond) {
		if ready([]string{"-key", file}) == nil {
			t.Fatal("ready passed for a forwarder that does not hold its capture port")
		}
		select {
		case err := <-failed:
			if err == nil {
				t.Fatal("forward returned without an error")
			}
			return
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("forward neither failed nor became ready")
		}
	}
}

// inNamespace, in the environment, marks the test process that runs in a network namespace of its own.
const inNamespace = "VSOCK_EGRESS_TEST_IN_NAMESPACE"

func TestRedirectSendsLookupsAndConnectionsToTheForwarder(t *testing.T) {
	if os.Getenv(inNamespace) == "" {
		if os.Geteuid() != 0 {
			t.Skip("only root can make a network namespace and redirect in it")
		}
		again := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$")
		again.Env = append(os.Environ(), inNamespace+"=1")
		again.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
		if out, err := again.CombinedOutput(); err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	lo, _ := unix.NewIfreq("lo")
	lo.SetUint16(unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, lo); err != nil {
		t.Fatalf("bring lo up: %v", err)
	}
	for run := range 2 { // an init container that is started again
		if err := redirect(nil); err != nil {
			t.Fatalf("run %d: %v", run+1, err)
		}
	}
	n := loadedNames(t, filepath.Join(t.TempDir(), "names"))
	queries, err := net.ListenPacket("udp4", captureAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer queries.Close()
	go n.resolve(queries)
	l, err := net.Listen("tcp4", captureAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.(*net.TCPListener).SetDeadline(time.Now().Add(budget))
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, "udp4", "127.0.0.1:53") // where a pod's resolv.conf points
	}}
	got, err := resolver.LookupNetIP(ctx, "ip4", "pypi.org")
	if err != nil || len(got) != 1 || !captureRange.Contains(got[0]) {
		t.Fatalf("a lookup at port 53 got %v, %v: want the forwarder's answer", got, err)
	}
	want := netip.AddrPortFrom(got[0], 8443)
	client, err := net.DialTimeout("tcp4", want.String(), budget)
	if err != nil {
		t.Fatalf("a connection to %v: %v", want, err)
	}
	defer client.Close()
	c, err := l.Accept()
	if err != nil {
		t.Fatalf("the connection did not reach the forwarder: %v", err)
	}
	defer c.Close()
	if to, err := originalDst(c.(*net.TCPConn)); err != nil || to != want {
		t.Fatalf("the forwarder took the connection to be for %v, %v: want %v", to, err, want)
	}
	if c, err := net.DialTimeout("tcp4", "192.0.2.1:443", budget); !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("a connection to an address outside %v: %v, %v: want no route", captureRange, c, err)
	}
}
