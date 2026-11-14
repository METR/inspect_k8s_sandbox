package main

import (
	"bufio"
	"bytes"
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
	"slices"
	"strings"
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

func TestNameHalfWrittenWhenTheForwarderWasKilledIsDropped(t *testing.T) {
	file := filepath.Join(t.TempDir(), "names")
	if err := os.WriteFile(file, []byte("pypi.org\nfiles.py"), 0o600); err != nil {
		t.Fatal(err)
	}
	n := loadedNames(t, file)
	pypi, _ := n.address("pypi.org")
	next, _ := n.address("next.example")
	if next != pypi.Next() {
		t.Fatalf("the name after pypi.org got %v, want %v: the half-written one was given to no program", next, pypi.Next())
	}
	if name, ok := loadedNames(t, file).name(next); !ok || name != "next.example" {
		t.Fatalf("after another restart %v is %q, %v: want next.example", next, name, ok)
	}
}

// question is one DNS message that asks for name, or with answered set, a reply to one.
func question(t *testing.T, name string, kind dnsmessage.Type, answered bool) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true, Response: answered})
	b.StartQuestions()
	if err := b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	query, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return query
}

// asked sends n one question as a resolver does and returns the reply's header and answers.
func asked(t *testing.T, n *names, name string, kind dnsmessage.Type) (dnsmessage.Header, []dnsmessage.Resource) {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(n.answer(question(t, name, kind, false)))
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
	// What is no query gets no answer and does not end the resolver: the forwarder would end with it.
	other, err := net.Dial("udp4", queries.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.Write([]byte("no DNS message"))
	if reply := n.answer(question(t, "pypi.org.", dnsmessage.TypeA, true)); reply != nil {
		t.Fatalf("a reply got the answer %x: two resolvers that answer each other never stop", reply)
	}

	got, err := resolver.LookupNetIP(ctx, "ip", "PyPI.org.") // IPv4 and IPv6, as getaddrinfo asks; rooted, so no search list is tried
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
	// Without its own names the pod's resolver would answer them as it answers this one, and the proxy would get the pod's connections to itself.
	if _, answers := asked(t, n, "default.example.", dnsmessage.TypeA); len(answers) != 1 || !captureRange.Contains(netip.AddrFrom4(answers[0].Body.(*dnsmessage.AResource).A)) {
		t.Fatalf("another name got %v: want an address that leads to the proxy", answers)
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

	unwritten := loadedNames(t, filepath.Join(t.TempDir(), "names"))
	unwritten.kept.Close()
	if h, answers := asked(t, unwritten, "pypi.org.", dnsmessage.TypeA); h.RCode != dnsmessage.RCodeServerFailure || len(answers) != 0 || len(unwritten.list) != 0 {
		t.Fatalf("a name that could not be written down got %v and %d answers: its address would not outlast a restart", h.RCode, len(answers))
	}
}

func TestForwarderWithoutItsCapturePortIsNotReady(t *testing.T) {
	if taken, err := net.Listen("tcp4", captureAddr); err == nil { // else another process holds it, which serves as well
		defer taken.Close()
	}
	file := filepath.Join(t.TempDir(), "key")
	failed := make(chan error, 1)
	go func() { failed <- forward([]string{"-listen", "127.0.0.1:0", "-key", file, "-capture"}) }()
	select {
	case err := <-failed:
		if !errors.As(err, new(*net.OpError)) { // where a profile refuses AF_VSOCK, forward fails later whatever it did here
			t.Fatalf("forward returned %v: want the error of its capture port", err)
		}
	case <-time.After(budget):
		t.Fatal("forward went on without its capture port")
	}
	if ready([]string{"-key", file}) == nil {
		t.Fatal("ready passed for a forwarder that does not hold its capture port")
	}
}

func TestTunnelReadsTheProxysReplyFrameByFrame(t *testing.T) {
	for name, tc := range map[string]struct {
		frames []string // the proxy's bytes, as the worker cut them into frames; the stream stays open after them
		opened bool
		rest   string // what the program is handed ahead of the tunnel's own bytes
	}{
		"a reply cut in two, and what follows it":  {[]string{"HTTP/1.1 200 Connec", "tion established\r\n\r\nhello"}, true, "hello"},
		"a proxy that ends its side with no reply": {[]string{"HTTP/1.1 200 Connec", ""}, false, ""},
		"a reply longer than a frame":              {[]string{"HTTP/1.1 200 " + strings.Repeat("x", maxFrame-13), "x\r\n\r\n"}, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			fromProxy, proxy := io.Pipe()
			t.Cleanup(func() { proxy.Close() })
			go func() {
				for _, f := range tc.frames {
					proxy.Write(frame(f))
				}
			}()
			var program bytes.Buffer
			opened := make(chan bool, 1)
			go func() {
				opened <- tunnel(struct {
					io.Reader
					io.Writer
				}{fromProxy, io.Discard}, &program, "pypi.org:443")
			}()
			select {
			case got := <-opened:
				if got != tc.opened || program.String() != tc.rest {
					t.Fatalf("the tunnel opened: %v, and the program was handed %q; want %v and %q", got, program.String(), tc.opened, tc.rest)
				}
			case <-time.After(budget):
				t.Fatal("the forwarder still waits for the proxy, and holds a stream's place while it does")
			}
		})
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
	configured, _ := net.InterfaceAddrs()
	if !slices.ContainsFunc(configured, func(a net.Addr) bool { return a.String() == captureRange.String() }) {
		t.Fatalf("the addresses are %v: glibc asks for a name's IPv4 address alone only where one other than 127.0.0.1 is configured", configured)
	}
	target, accepted := proxy(t)
	f := keyedForwarder(0, 0)
	now := make(chan struct{}) // the node learns of a stream's end at once
	close(now)
	lagging(t, f, newWorker(firecracker(t, map[uint32]string{keyPort: string(f.key[:])}), target, 0), now)
	if err := f.capture(filepath.Join(t.TempDir(), "names"), nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return new(net.Dialer).DialContext(ctx, "udp4", "127.0.0.1:53") // where a pod's resolv.conf points
	}}
	got, err := resolver.LookupNetIP(ctx, "ip4", "pypi.org.")
	if err != nil || len(got) != 1 || !captureRange.Contains(got[0]) {
		t.Fatalf("a lookup at port 53 got %v, %v: want the forwarder's answer", got, err)
	}
	pypi := netip.AddrPortFrom(got[0], 8443).String()
	// connected is a program's connection to an address, and the first thing it reads there.
	connected := func(to string, read []byte) (net.Conn, int, error) {
		c, err := net.DialTimeout("tcp4", to, budget)
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
		c := within(t, accepted, "connection at the proxy")
		c.SetDeadline(time.Now().Add(budget))
		r := bufio.NewReader(c)
		if request, err := http.ReadRequest(r); err != nil || request.Method != "CONNECT" || request.Host != "pypi.org:8443" {
			t.Fatalf("the proxy read %+v, %v: want CONNECT pypi.org:8443", request, err)
		}
		return c, r
	}

	client, _, err := connected(pypi, nil)
	if err != nil {
		t.Fatalf("a connection to %v: %v", pypi, err)
	}
	atProxy, fromClient := asks()
	atProxy.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\nhello")) // a server that speaks first
	client.Write([]byte("ping"))
	read := make([]byte, 5)
	if _, err := io.ReadFull(client, read); string(read) != "hello" {
		t.Fatalf("the program read %q, %v: want what follows the proxy's reply", read, err)
	}
	if _, err := io.ReadFull(fromClient, read[:4]); string(read[:4]) != "ping" {
		t.Fatalf("the proxy read %q, %v inside the tunnel", read[:4], err)
	}

	if client, _, err = connected(pypi, nil); err != nil {
		t.Fatal(err)
	}
	atProxy, _ = asks()
	atProxy.Write([]byte("HTTP/1.1 403 Forbidden\r\ncontent-length: 2\r\n\r\nno"))
	if n, err := client.Read(read); n != 0 || !errors.Is(err, unix.ECONNRESET) {
		t.Fatalf("the program read %q, %v from a connection the proxy refused: want a reset", read[:n], err)
	}

	for name, to := range map[string]string{
		"an address no name was given":    netip.AddrPortFrom(got[0].Next(), 443).String(),
		"a connection nothing redirected": captureAddr,
	} {
		if _, n, err := connected(to, read); n != 0 || !errors.Is(err, unix.ECONNRESET) {
			t.Fatalf("%s: the program read %q, %v: want a reset", name, read[:n], err)
		}
		if len(accepted) != 0 {
			t.Fatalf("%s: the connection reached the proxy", name)
		}
	}
	if c, err := net.DialTimeout("tcp4", "192.0.2.1:443", budget); !errors.Is(err, unix.ENETUNREACH) {
		t.Fatalf("a connection to an address outside %v: %v, %v: want no route", captureRange, c, err)
	}
}
