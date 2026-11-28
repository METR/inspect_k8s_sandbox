package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// firecracker stands in for a VM's vsock socket on the node: it answers CONNECT for a guest port with what a guest process listening there would say first.
func firecracker(t *testing.T, says map[uint32]string) (vsock string) {
	t.Helper()
	return firecrackerThat(t, func(port uint32) (string, bool) {
		say, ok := says[port]
		return say, ok
	})
}

// firecrackerThat is firecracker for a guest whose ports do not always say the same.
func firecrackerThat(t *testing.T, says func(port uint32) (say string, listening bool)) (vsock string) {
	t.Helper()
	return firecrackerWith(t, says, nil)
}

// firecrackerWith is firecrackerThat for a guest that also takes its siblings' connections: arrive gets each one the node makes to inboundPort.
func firecrackerWith(t *testing.T, says func(port uint32) (say string, listening bool), arrive func(net.Conn)) (vsock string) {
	t.Helper()
	vsock = filepath.Join(t.TempDir(), "vm.vsock")
	l, err := net.Listen("unix", vsock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			var port uint32
			fmt.Fscanf(bufio.NewReader(c), "CONNECT %d\n", &port)
			if port == inboundPort && arrive != nil {
				t.Cleanup(func() { c.Close() })
				fmt.Fprint(c, "OK 1073741824\n")
				go arrive(c)
				continue
			}
			if say, ok := says(port); ok { // with no listener in the guest, Firecracker closes without a word
				fmt.Fprintf(c, "OK 1073741824\n%s", say)
			}
			c.Close()
		}
	}()
	return vsock
}

// holding is what a guest's ports say where its forwarder holds key and serves nothing else.
func holding(key []byte) func(uint32) (string, bool) {
	return func(port uint32) (string, bool) { return string(key), port == keyPort }
}

// proxy is a TCP server that hands over each connection it accepts.
func proxy(t *testing.T) (address string, accepted chan net.Conn) {
	t.Helper()
	return serverAt(t, "127.0.0.1:0")
}

// serverAt is proxy at an address of the test's choosing.
func serverAt(t *testing.T, at string) (address string, accepted chan net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", at)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	accepted = make(chan net.Conn, 2*workerStreams)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
			accepted <- c
		}
	}()
	return l.Addr().String(), accepted
}

// served starts a worker for a VM whose forwarder holds key, and returns a dial for the guest's side.
func served(t *testing.T, key []byte, target string, pace *pacer) (dial func() net.Conn) {
	t.Helper()
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), target, 0)
	w.pace = pace
	return serve(t, w)
}

// serve starts w at its VM's stream socket, and returns a dial for the guest's side.
func serve(t *testing.T, w *worker) (dial func() net.Conn) {
	t.Helper()
	return serveAt(t, w, streamPort, w.proxied)
}

// serveAt starts w at its VM's socket for one vsock port, and returns a dial for the guest's side.
func serveAt(t *testing.T, w *worker, port int, carry func(net.Conn)) (dial func() net.Conn) {
	t.Helper()
	streams := fmt.Sprintf("%s_%d", w.vsock, port)
	l, err := net.Listen("unix", streams)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go w.serve(l, carry)
	return func() net.Conn {
		c, err := net.Dial("unix", streams)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(budget))
		t.Cleanup(func() { c.Close() })
		return c
	}
}

// closed is closed when the worker has closed c.
func closed(c net.Conn) chan struct{} {
	done := make(chan struct{})
	go func() {
		io.Copy(io.Discard, c)
		close(done)
	}()
	return done
}

// within returns what ch gives, and fails the test once the budget has passed with nothing.
func within[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(budget):
		t.Fatalf("no %s in %v", what, budget)
		panic("unreachable")
	}
}

func newKey() []byte {
	key := make([]byte, keySize)
	rand.Read(key)
	return key
}

// relayed starts w at a TCP port that stands for its pod's relay port, and returns a dial for a sibling's worker.
func relayed(t *testing.T, w *worker) (dial func() *net.TCPConn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go w.serve(l, w.arrive)
	return func() *net.TCPConn {
		c, err := net.DialTimeout("tcp", l.Addr().String(), budget)
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(budget))
		t.Cleanup(func() { c.Close() })
		return c.(*net.TCPConn)
	}
}

// reset reads to its end a connection that is to be reset at once: the reset may land before the dial returns, which then fails with it.
func reset(c net.Conn, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(budget))
	return io.Copy(io.Discard, c)
}

func TestSiblingStreamReachesTheWorkerOfTheSiblingItsAddressStandsFor(t *testing.T) {
	out := capture(t)
	key := newKey()
	_, accepted := serverAt(t, fmt.Sprintf("127.0.0.1:%d", relayPort)) // where every worker takes its siblings' connections
	other, _ := proxy(t)
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), other, 0)
	if err := w.annotated("198.18.0.2=localhost,198.18.0.4=127.0.0.3", ""); err != nil { // the second where no worker listens
		t.Fatal(err)
	}
	dial := serveAt(t, w, siblingPort, w.sibling)

	c := dial()
	c.Write(append(append(key, "\xc6\x12\x00\x02\x1f\x40"...), frame("request")...)) // 198.18.0.2, port 8000
	got := within(t, accepted, "connection to the sibling's worker")
	got.SetDeadline(time.Now().Add(budget))
	hello := make([]byte, 2+len("request"))
	if _, err := io.ReadFull(got, hello); err != nil || string(hello) != "\x1f\x40request" {
		t.Fatalf("the sibling's worker read %q, %v: want port 8000 as two bytes and then the request", hello, err)
	}

	c = dial()
	c.Write(append(append(key, "\xc6\x12\x00\x03\x1f\x40"...), frame("request")...)) // 198.18.0.3
	c.SetReadDeadline(time.Now().Add(budget))
	if _, err := io.Copy(io.Discard, c); errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("a stream for an address that is no sibling's was not closed")
	}

	c = dial()
	c.Write(append(key, "\xc6\x12\x00\x04\x1f\x40"...)) // 198.18.0.4
	c.SetReadDeadline(time.Now().Add(budget))
	io.Copy(io.Discard, c)
	w.report()
	out.Lock()
	defer out.Unlock()
	if !strings.Contains(out.String(), "sibling_unreached: dial tcp 127.0.0.3:") || strings.Count(out.String(), "sibling_unreached: ") != 2 {
		t.Fatalf("the log is %q: want the word an alarm reads for a sibling whose worker is gone, with why, and once more in the report", out.String())
	}
}

func TestSiblingsConnectionEntersTheGuestOnlyAfterTheForwardersKey(t *testing.T) {
	for name, tc := range map[string]struct {
		shown func(key []byte) []byte // what holds the guest's inbound port shows
		ports string
		said  string // the word an alarm reads, for a connection that does not enter
	}{
		"the forwarder, every port served":   {func(key []byte) []byte { return key }, "*", ""},
		"the forwarder, that port served":    {func(key []byte) []byte { return key }, "22,8000", ""},
		"the forwarder, another port served": {func(key []byte) []byte { return key }, "22", "streams_refused: "},
		"another process on the vsock port":  {func([]byte) []byte { return newKey() }, "*", "guest_unreached: "},
	} {
		t.Run(name, func(t *testing.T) {
			out := capture(t)
			key := newKey()
			took := make(chan string, 1)
			w := newWorker(firecrackerWith(t, holding(key), func(guest net.Conn) {
				guest.SetDeadline(time.Now().Add(budget))
				guest.Write(tc.shown(key))
				port := make([]byte, 2)
				var request bytes.Buffer
				if _, err := io.ReadFull(guest, port); err != nil || fromFrames(&request, guest, nil) != nil {
					took <- ""
					return
				}
				toFrames(guest, strings.NewReader("reply"), nil)
				took <- string(port) + request.String()
			}), "", 0)
			if err := w.annotated("", tc.ports); err != nil {
				t.Fatal(err)
			}
			c := relayed(t, w)()
			sent := "\x1f\x40request"
			if tc.said != "" {
				sent = sent[:2] // the port alone: a worker that closes on bytes it has not read resets the connection whatever it meant to
			}
			c.Write([]byte(sent))
			c.CloseWrite()
			reply, err := io.ReadAll(c)
			if tc.said != "" {
				select {
				case got := <-took:
					if got != "" {
						t.Fatalf("the guest took %q", got)
					}
				default: // the guest was never asked
				}
				w.report()
				out.Lock()
				defer out.Unlock()
				if !errors.Is(err, syscall.ECONNRESET) || strings.Count(out.String(), tc.said) != 2 {
					t.Fatalf("the sibling's worker read %q, %v, and the log is %q: want a reset, as a closed port gives, and %q at once and in the report", reply, err, out.String(), tc.said)
				}
				return
			}
			if got := within(t, took, "connection in the guest"); got != "\x1f\x40request" || string(reply) != "reply" || err != nil {
				t.Fatalf("the guest took %q and the sibling's worker read %q, %v: want port 8000, the request, and the reply back", got, reply, err)
			}
		})
	}
}

func TestSiblingsConnectionThatNamesNoPortIsReset(t *testing.T) {
	w := newWorker(firecracker(t, nil), "", 0)
	w.keyWait = 0
	if err := w.annotated("", "*"); err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go w.serve(l, w.arrive)
	// Left to wait, 64 of them would be every place its siblings have.
	if _, err := reset(net.DialTimeout("tcp", l.Addr().String(), budget)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("a silent connection from a sibling ended with %v: want it reset", err)
	}
}

func TestSiblingsHoldNoMoreThanHalfOfAPodsPlaces(t *testing.T) {
	w := newWorker(firecracker(t, nil), "", 0)
	w.keyWait = time.Hour // no silent connection gives its place up while the test runs
	if err := w.annotated("", "*"); err != nil {
		t.Fatal(err)
	}
	dial := relayed(t, w)
	var at string
	for held := 1; held <= maxStreams; held++ {
		at = dial().RemoteAddr().String()
		for deadline := time.Now().Add(budget); len(w.arriving) < held; time.Sleep(time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("the worker took %d of its siblings' connections, want %d", len(w.arriving), held)
			}
		}
	}
	// With every place taken, the pod's own streams to its proxy and its siblings would be refused instead.
	if _, err := reset(net.DialTimeout("tcp", at, budget)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("one more connection from a sibling ended with %v: want it reset at once", err)
	}
	if open := len(w.unkeyed); open != maxStreams {
		t.Fatalf("its siblings hold %d of the pod's %d places, want %d", open, workerStreams, maxStreams)
	}
}

func TestSiblingsConnectionsGiveBackTheirPlaces(t *testing.T) {
	key := newKey()
	target, accepted := proxy(t)
	entered := make(chan struct{}, 1)
	w := newWorker(firecrackerWith(t, holding(key), func(guest net.Conn) {
		guest.Write(key)
		entered <- struct{}{}
	}), target, 0)
	if err := w.annotated("", "22"); err != nil {
		t.Fatal(err)
	}
	sibling := relayed(t, w)
	for range workerStreams {
		c := sibling()
		c.Write([]byte("\x1f\x40")) // port 8000, which the pod does not serve
		io.Copy(io.Discard, c)
	}
	// Each was a place among the pod's 128 until its port was read: kept, they would shut the pod's own streams out.
	c := serve(t, w)()
	c.Write(key)
	within(t, accepted, "the pod's stream to its proxy")
	// And one of the 64 its siblings may hold, until it ended: kept, they would shut its siblings out.
	sibling().Write([]byte("\x00\x16")) // port 22
	within(t, entered, "connection from a sibling into the guest")
}

func TestSiblingIsLookedUpAgainOnceItsAddressIsStale(t *testing.T) {
	key := newKey()
	_, first := serverAt(t, fmt.Sprintf("127.0.0.1:%d", relayPort))
	_, second := serverAt(t, fmt.Sprintf("127.0.0.2:%d", relayPort)) // where the Service points once the sibling's pod is replaced
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), "", 0)
	if err := w.annotated("198.18.0.2=game.test", ""); err != nil {
		t.Fatal(err)
	}
	var clock, lookups atomic.Int64
	w.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	w.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr(fmt.Sprintf("127.0.0.%d", min(lookups.Add(1), 2)))}, nil
	}
	dial := serveAt(t, w, siblingPort, w.sibling)
	stream := func() { dial().Write(append(key, "\xc6\x12\x00\x02\x1f\x40"...)) }

	stream()
	within(t, first, "connection to the sibling's first address")
	clock.Store(int64(siblingFresh/time.Second) - 1)
	stream()
	within(t, first, "connection to the address the worker still holds")
	clock.Store(int64(siblingFresh / time.Second))
	stream()
	within(t, second, "connection to the sibling's new address")
}

// working starts the real work for a pod whose guest shows key, and returns its vsock socket and what the guest takes of each connection handed into it.
func working(t *testing.T, key []byte, flags ...string) (vsock string, took <-chan string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("a worker does not run as root")
	}
	taken := make(chan string, 1)
	vsock = firecrackerWith(t, holding(key), func(guest net.Conn) {
		guest.SetDeadline(time.Now().Add(budget))
		guest.Write(key)
		hello := make([]byte, 2+4+len("request"))
		io.ReadFull(guest, hello)
		taken <- string(hello)
	})
	worker := exec.Command(os.Args[0], append([]string{"work", "-pod", "ns/pod", "-vsock", vsock}, flags...)...)
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		worker.Process.Kill()
		worker.Wait()
	})
	for deadline := time.Now().Add(budget); ; time.Sleep(10 * time.Millisecond) { // it serves once its socket is there
		if c, err := net.Dial("unix", fmt.Sprintf("%s_%d", vsock, siblingPort)); err == nil {
			c.Close()
			return vsock, taken
		} else if time.Now().After(deadline) {
			t.Fatalf("the worker did not come to listen for its pod's connections to siblings: %v", err)
		}
	}
}

func TestWorkerStartedForAPodWithSiblingsCarriesItToThemAndThemToIt(t *testing.T) {
	key := newKey()
	// The pod's one sibling is this machine, so the connection comes back to the same worker, as one from a sibling.
	vsock, took := working(t, key, "-siblings", "198.18.0.2=localhost", "-ports", "8000")
	c, err := net.Dial("unix", fmt.Sprintf("%s_%d", vsock, siblingPort))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write(append(append(key, "\xc6\x12\x00\x02\x1f\x40"...), frame("request")...)) // to 198.18.0.2, port 8000
	if got, want := within(t, took, "connection in the guest"), "\x1f\x40"+string(frame("request")); got != want {
		t.Fatalf("the guest took %q: want port 8000 and the request, in frames", got)
	}
}

func TestWorkerTakesAConnectionToAPortItsPodListensOnIntoTheGuestAtThatPort(t *testing.T) {
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := free.Addr().(*net.TCPAddr).Port
	free.Close()
	_, took := working(t, newKey(), "-listen", strconv.Itoa(port))
	// At an address other than the one the port was found at: a caller comes to the pod's own, which a listener on 127.0.0.1 alone would refuse.
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.2:%d", port), budget)
	if err != nil {
		t.Fatalf("the worker does not listen on port %d of every address: %v", port, err)
	}
	defer c.Close()
	c.Write([]byte("request")) // a client that knows nothing of the relay: it names no port
	if got, want := within(t, took, "connection in the guest"), string([]byte{byte(port >> 8), byte(port)})+string(frame("request")); got != want {
		t.Fatalf("the guest took %q: want port %d and the request, in frames", got, port)
	}
}

func TestStreamWithoutTheKeyReachesNothing(t *testing.T) {
	key := newKey()
	target, accepted := proxy(t)
	dial := served(t, key, target, nil)

	intruder := dial() // a workload process that opened the vsock itself
	intruder.Write(append(newKey(), frame("CONNECT evil.example:443 HTTP/1.1\r\n\r\n")...))
	select {
	case <-accepted:
		t.Fatal("a stream that did not open with the key reached the proxy")
	case <-closed(intruder):
	case <-time.After(budget):
		t.Fatal("the stream was neither refused nor joined")
	}

	forwarder := dial()
	forwarder.Write(append(key, frame("ping")...))
	select {
	case c := <-accepted:
		got := make([]byte, 4)
		c.SetDeadline(time.Now().Add(budget))
		if _, err := io.ReadFull(c, got); string(got) != "ping" {
			t.Fatalf("the proxy read %q, %v", got, err)
		}
	case <-time.After(budget):
		t.Fatal("a stream that opened with the key did not reach the proxy")
	}
}

// logged collects what the test's workers write to the log.
type logged struct {
	sync.Mutex
	bytes.Buffer
}

func (l *logged) Write(p []byte) (int, error) {
	l.Lock()
	defer l.Unlock()
	return l.Buffer.Write(p)
}

// capture sends the log to the buffer it returns until the test ends.
func capture(t *testing.T) *logged {
	out := &logged{}
	was := log.Writer()
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(was) })
	return out
}

func TestRefusedStreamsAreCountedNotLoggedOneByOne(t *testing.T) {
	out := capture(t)
	target, _ := proxy(t)
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(newKey())}), target, 0)
	dial := serve(t, w)

	const refused = 50
	for range refused {
		c := dial()
		c.Write(newKey())
		select {
		case <-closed(c):
		case <-time.After(budget):
			t.Fatal("a stream without the key was not closed")
		}
	}
	out.Lock()
	written := out.String()
	out.Unlock()
	if strings.Count(written, "\n") != 1 || !strings.Contains(written, "streams_refused: a stream with no key") {
		t.Fatalf("%d lines were written as the streams were refused, %q: want the first said at once, and no other", strings.Count(written, "\n"), written)
	}
	w.report()
	w.report() // nothing more was refused since the first
	out.Lock()
	defer out.Unlock()
	if want := fmt.Sprintf("streams_refused: %d since the last report\n", refused); !strings.HasSuffix(out.String(), want) || strings.Count(out.String(), "\n") != 2 {
		t.Fatalf("the log is %q, want one more line, %q: no stream failed in any other way, or since", out.String(), want)
	}
}

func TestNewStreamsAreTakenAtABoundedRate(t *testing.T) {
	var mu sync.Mutex
	clock, slept := time.Unix(0, 0), time.Duration(0)
	const streams = 2 * newStreams
	target, _ := proxy(t)
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(newKey())}), target, 0)
	if w.accepts == nil {
		t.Fatal("a worker has no pacer for new streams")
	}
	w.accepts.now = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}
	w.accepts.sleep = func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		clock, slept = clock.Add(d), slept+d
	}
	dial := serve(t, w)

	for range streams {
		c := dial()
		c.Write(newKey())
		select {
		case <-closed(c):
		case <-time.After(budget):
			t.Fatal("a stream without the key was not closed")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if least := streams/newStreams*time.Second - 3*paceSlack; slept < least {
		t.Fatalf("taking %d streams at %d a second waited %v: want at least %v", streams, newStreams, slept, least)
	}
}

func TestFailedKeyFetchesAreCountedNotLoggedOneByOne(t *testing.T) {
	out := capture(t)
	target, _ := proxy(t)
	w := newWorker(firecracker(t, nil), target, 0) // nothing in the guest holds the key port
	var clock atomic.Int64
	w.now = func() time.Time { return time.Unix(clock.Add(1), 0) } // a second on for each stream: each asks for the key again
	dial := serve(t, w)

	const fetches = 5
	for range fetches {
		c := dial()
		c.Write(newKey())
		select {
		case <-closed(c):
		case <-time.After(budget):
			t.Fatal("a stream was not closed while there was no key to fetch")
		}
	}
	out.Lock()
	lines := strings.Count(out.String(), fmt.Sprintf("key_unfetched: guest vsock port %d", keyPort))
	out.Unlock()
	if lines != 1 {
		t.Fatalf("%d lines say why the key was not fetched: want 1 until the report", lines)
	}
	w.report()
	w.report() // no fetch failed since the first
	out.Lock()
	defer out.Unlock()
	if want := fmt.Sprintf("key_unfetched: %d fetches since the last report", fetches); !strings.Contains(out.String(), want) || strings.Count(out.String(), "since the last report") != 2 {
		t.Fatalf("the reports are %q, want %q in them once, beside the refusals'", out.String(), want)
	}
}

func TestWorkerRefusesToRunAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second) // a worker that starts would serve until killed
	defer cancel()
	out, err := exec.CommandContext(ctx, os.Args[0], "work", "-pod", "ns/pod", "-vsock", filepath.Join(t.TempDir(), "vm.vsock")).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "never as root") {
		t.Fatalf("got %v and %q: want a worker that refuses to run as root", err, out)
	}
}

func TestWorkerIsWhatTheKernelEndsFirstWhenMemoryIsOut(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a worker does not run as root")
	}
	vsock := filepath.Join(t.TempDir(), "vm.vsock")
	worker := exec.Command(os.Args[0], "work", "-pod", "ns/pod", "-vsock", vsock, "-target", "proxy.ns.svc.cluster.local:3128")
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	defer worker.Wait()
	defer worker.Process.Kill()
	for deadline := time.Now().Add(budget); ; time.Sleep(10 * time.Millisecond) { // it serves once its socket is there
		if _, err := os.Stat(fmt.Sprintf("%s_%d", vsock, streamPort)); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatal("the worker did not come to listen")
		}
	}
	score, err := os.ReadFile(fmt.Sprintf("/proc/%d/oom_score_adj", worker.Process.Pid))
	if err != nil || strings.TrimSpace(string(score)) != "1000" {
		t.Fatalf("its oom_score_adj is %q, %v: want 1000, or the kernel ends the launcher, and with it every worker", score, err)
	}
}

func TestWorkerThatEndsWithAnErrorSaysSoInTheWordAnAlarmReads(t *testing.T) {
	out, err := exec.Command(os.Args[0], "work", "-pod", "ns/pod", "-vsock", filepath.Join(t.TempDir(), "none", "vm.vsock")).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "ns/pod: work_failed: ") {
		t.Fatalf("got %v and %q: want a worker with nowhere to listen to end with work_failed", err, out)
	}
}

func TestKeyIsFetchedOnceForAWorker(t *testing.T) {
	key, other := newKey(), newKey()
	var held atomic.Pointer[[]byte] // the key that whoever holds the guest's key port gives
	held.Store(&key)
	target, accepted := proxy(t)
	w := newWorker(firecrackerThat(t, func(port uint32) (string, bool) { return string(*held.Load()), port == keyPort }), target, 0)
	var clock atomic.Int64
	w.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	dial := serve(t, w)
	dial().Write(key)
	select {
	case <-accepted:
	case <-time.After(budget):
		t.Fatal("the forwarder's stream reached nothing")
	}

	// A minute on, the forwarder has died and a workload process holds the guest's key port, with a key of its own.
	held.Store(&other)
	clock.Add(60)
	intruder := dial()
	intruder.Write(other)
	select {
	case <-accepted:
		t.Fatal("a stream reached the proxy with a key the worker fetched after its first")
	case <-closed(intruder):
	case <-time.After(budget):
		t.Fatal("the stream was neither refused nor joined")
	}
}

func TestKeyIsAskedForAtMostOnceASecond(t *testing.T) {
	var asked, clock atomic.Int64
	target, _ := proxy(t)
	w := newWorker(firecrackerThat(t, func(uint32) (string, bool) {
		asked.Add(1)
		return "", false // no forwarder holds the key port yet
	}), target, 0)
	w.now = func() time.Time { return time.Unix(clock.Load(), 0) }
	dial := serve(t, w)
	stream := func() {
		c := dial()
		c.Write(newKey())
		select {
		case <-closed(c):
		case <-time.After(budget):
			t.Fatal("a stream was not closed while there was no key to fetch")
		}
	}

	for range 5 {
		stream()
	}
	if n := asked.Load(); n != 1 {
		t.Fatalf("5 streams within a second asked the guest for its key %d times: want once", n)
	}
	clock.Add(1)
	stream()
	if n := asked.Load(); n != 2 {
		t.Fatalf("a stream a second later brought the asks to %d: want 2", n)
	}
}

func TestStreamsDoNotWaitForEachOthersLookup(t *testing.T) {
	key := newKey()
	target, accepted := proxy(t)
	_, port, _ := net.SplitHostPort(target)
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), net.JoinHostPort("proxy.test", port), 0)
	var lookups atomic.Int32
	hang := make(chan struct{})
	t.Cleanup(func() { close(hang) })
	w.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		if lookups.Add(1) == 1 {
			<-hang // the cluster's DNS has no answer for one stream
		}
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}
	dial := serve(t, w)

	dial().Write(key)
	dial().Write(key)
	within(t, accepted, "stream at the proxy while another stream's lookup hangs")
}

func TestProxyNamedByHostIsLookedUp(t *testing.T) {
	key := newKey()
	target, accepted := proxy(t)
	_, port, _ := net.SplitHostPort(target)
	c := served(t, key, net.JoinHostPort("localhost", port), nil)()

	c.Write(key)
	select {
	case <-accepted:
	case <-closed(c):
		t.Fatal("a stream for a proxy named by host was closed")
	case <-time.After(budget):
		t.Fatal("a stream for a proxy named by host reached nothing")
	}
}

func TestProxyIsLookedUpAgainAfterADialFails(t *testing.T) {
	out := capture(t)
	key := newKey()
	target, accepted := proxy(t)
	_, port, _ := net.SplitHostPort(target)
	// The proxy's pod was replaced: its name first gives an address where nothing listens any more.
	answers := []string{"127.0.0.2", "127.0.0.1"}
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), net.JoinHostPort("proxy.test", port), 0)
	var clock atomic.Int64
	w.now = func() time.Time { return time.Unix(clock.Add(1), 0) } // a second on for each reading: the dial fails a second after the lookup
	w.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		answer := netip.MustParseAddr(answers[0])
		answers = answers[min(1, len(answers)-1):]
		return []netip.Addr{answer}, nil
	}
	dial := serve(t, w)

	first := dial()
	first.Write(key)
	select {
	case <-accepted:
		t.Fatal("the first stream reached the proxy at an address it has left")
	case <-closed(first):
	case <-time.After(budget):
		t.Fatal("the first stream was neither joined nor closed")
	}
	w.report()
	w.report() // no stream failed since the first
	if want := "proxy_unreached: 1 streams since the last report\n"; !strings.HasSuffix(out.String(), want) || !strings.Contains(out.String(), "proxy_unreached: dial tcp ") || strings.Count(out.String(), "\n") != 2 {
		t.Fatalf("the log is %q, want one line at once that says why and one report's %q, and no other", out.String(), want)
	}
	second := dial()
	second.Write(key)
	select {
	case <-accepted:
	case <-closed(second):
		t.Fatal("the worker kept the address where nothing listens")
	case <-time.After(budget):
		t.Fatal("the second stream was neither joined nor closed")
	}
}

func TestStreamEndedBeforeItsProxyCouldBeDialledIsNoFailure(t *testing.T) {
	out := capture(t)
	key := newKey()
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), "127.0.0.2:9", 0) // where nothing listens
	guest, node := net.Pipe()
	go func() { // as the forwarder's startup probe does, before the pod's proxy is there
		guest.Write(key)
		guest.Close()
	}()
	w.unkeyed <- struct{}{}
	w.proxied(node)
	w.report()
	if out.String() != "" {
		t.Fatalf("the log is %q: want nothing for a stream its guest had ended", out.String())
	}
}

func TestStreamToTheProxyOfAPodThatNamesNoneIsRefused(t *testing.T) {
	out := capture(t)
	key := newKey()
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), "", 0) // as for a pod that has siblings and no proxy
	c := serve(t, w)()
	c.Write(key)
	select {
	case <-closed(c):
	case <-time.After(budget):
		t.Fatal("the stream was not closed")
	}
	w.report()
	if !strings.Contains(out.String(), "streams_refused") || strings.Contains(out.String(), "proxy_unreached") {
		t.Fatalf("the log is %q: want the stream among those a sandbox can have refused, and no word the proxy's alarm reads", out.String())
	}
}

func TestProxyThatIsDownIsLookedUpAtMostOnceASecond(t *testing.T) {
	for name, unresolved := range map[string]error{"nothing listens at its address": nil, "its name does not resolve": errors.New("no such host")} {
		t.Run(name, func(t *testing.T) {
			var lookups, clock atomic.Int64
			key := newKey()
			target, _ := proxy(t)
			_, port, _ := net.SplitHostPort(target)
			w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), net.JoinHostPort("proxy.test", port), 0)
			w.now = func() time.Time { return time.Unix(clock.Load(), 0) }
			w.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
				lookups.Add(1)
				return []netip.Addr{netip.MustParseAddr("127.0.0.2")}, unresolved // where nothing listens
			}
			dial := serve(t, w)
			stream := func() {
				c := dial()
				c.Write(key)
				select {
				case <-closed(c):
				case <-time.After(budget):
					t.Fatal("a stream was not closed while its proxy was down")
				}
			}

			for range 5 {
				stream()
			}
			if n := lookups.Load(); n != 1 {
				t.Fatalf("5 streams within a second looked the proxy up %d times: want once", n)
			}
			clock.Add(1)
			stream() // its failed dial gives the address up, or it asks again
			stream()
			if n := lookups.Load(); n != 2 {
				t.Fatalf("streams a second later brought the lookups to %d: want 2", n)
			}
		})
	}
}

func TestConnectionsThatSendNoKeyTakeNoStreamsPlace(t *testing.T) {
	key := newKey()
	target, accepted := proxy(t)
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), target, 0)
	dial := serve(t, w)

	for range workerStreams - 1 { // a guest process dials and says nothing
		dial()
	}
	forwarder := dial()
	forwarder.Write(key)
	select {
	case <-accepted:
	case <-closed(forwarder):
		t.Fatal("the forwarder's stream was refused while silent connections were open")
	case <-time.After(budget):
		t.Fatal("the forwarder's stream reached nothing")
	}
	if held := len(w.slots); held != 1 {
		t.Fatalf("%d connections hold a stream's place: want the forwarder's alone", held)
	}
}

func TestConnectionPastThoseThatHaveShownNoKeyIsClosed(t *testing.T) {
	target, _ := proxy(t)
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(newKey())}), target, 0)
	w.keyWait = time.Hour // no silent connection gives its place up while the test runs
	dial := serve(t, w)

	for range workerStreams {
		dial()
	}
	if _, err := dial().Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("connection %d that showed no key ended with %v: want it closed at once", workerStreams+1, err)
	}
}

// buffers is what the kernel holds a socket's buffers to, to take from its peer and to send it: all a test can read of a cap.
func buffers(t *testing.T, c syscall.Conn) (each [2]int) {
	t.Helper()
	raw, err := c.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	raw.Control(func(fd uintptr) {
		for i, option := range []int{syscall.SO_RCVBUF, syscall.SO_SNDBUF} {
			if each[i], err = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, option); err != nil {
				t.Error(err)
			}
		}
	})
	return each
}

// capped is what buffers reads of a socket whose buffers are set to size: the kernel takes twice what is asked, up to its own maximum.
func capped(t *testing.T, size int) (each [2]int) {
	t.Helper()
	for i, sysctl := range []string{"rmem_max", "wmem_max"} {
		b, err := os.ReadFile("/proc/sys/net/core/" + sysctl)
		most, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		if err != nil || most <= 0 {
			t.Skipf("cannot read the kernel's %s: %v", sysctl, err)
		}
		each[i] = 2 * min(most, size)
	}
	return each
}

func TestProxySocketIsCappedEachWay(t *testing.T) {
	target, _ := proxy(t)
	w := newWorker("", target, 0)
	c, err := w.dial(w.proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if got, want := buffers(t, c.(*net.TCPConn)), capped(t, proxyBuffer); got != want {
		t.Fatalf("the socket to the proxy holds %v bytes each way: want %v, the kernel's count of the cap", got, want)
	}
}

func TestStreamWhoseProxyTakesNothingIsCutShort(t *testing.T) {
	key := newKey()
	target, accepted := proxy(t)
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), target, 0)
	if w.stall <= 0 {
		t.Fatal("a worker gives a write to its proxy no bound")
	}
	w.stall = 100 * time.Millisecond
	c := serve(t, w)()
	c.Write(key)
	up := within(t, accepted, "stream at the proxy")
	up.SetReadDeadline(time.Now().Add(budget))
	for range 4 { // while the proxy takes what it is sent, an upload may last longer than the wait
		c.Write(frame("part"))
		if _, err := io.ReadFull(up, make([]byte, len("part"))); err != nil {
			t.Fatalf("the proxy read no more of an upload it was taking: %v", err)
		}
		time.Sleep(w.stall / 2)
	}
	go toFrames(c, zeros{}, nil) // the proxy reads no more: this upload stops once every buffer on the way to it is full
	c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if reply, err := io.ReadAll(c); errors.Is(err, os.ErrDeadlineExceeded) || len(reply) != 0 {
		t.Fatalf("the guest read %q, %v: want the stream ended, and with no frame, as one cut short", reply, err)
	}
}

func TestStreamPastTheCapIsRefused(t *testing.T) {
	key := newKey()
	target, accepted := proxy(t)
	dial := served(t, key, target, nil)

	open := make([]net.Conn, workerStreams)
	for i := range open {
		open[i] = dial()
		open[i].Write(key)
	}
	for range open {
		select {
		case <-accepted:
		case <-time.After(budget):
			t.Fatalf("fewer than %d streams reached the proxy", workerStreams)
		}
	}
	extra := dial()
	extra.Write(key)
	select {
	case <-accepted:
		t.Fatalf("stream %d reached the proxy", workerStreams+1)
	case <-closed(extra):
	case <-time.After(budget):
		t.Fatalf("stream %d was neither refused nor joined", workerStreams+1)
	}

	open[0].Close() // its slot comes back once the worker has seen the close
	for deadline := time.Now().Add(budget); ; {
		next := dial()
		next.Write(key)
		select {
		case <-accepted:
			return
		case <-closed(next):
		}
		if time.Now().After(deadline) {
			t.Fatal("no stream was let in after one had ended")
		}
	}
}

func TestCancelledStreamKeepsItsSlotUntilItHasStopped(t *testing.T) {
	asleep, wake := make(chan struct{}, 1), make(chan struct{})
	t.Cleanup(func() { close(wake) })
	key := newKey()
	target, accepted := proxy(t)
	// Slow enough that one byte waits: the stream's goroutine sleeps in the pacer, holding its buffer.
	pace := &pacer{rate: 1, now: time.Now, sleep: func(time.Duration) {
		asleep <- struct{}{}
		<-wake
	}}
	dial := served(t, key, target, pace)

	cancelled := dial()
	cancelled.Write(key)
	up := within(t, accepted, "stream at the proxy")
	up.Write([]byte("reply"))
	within(t, asleep, "sleep in the pacer")
	cancelled.Close()
	up.SetDeadline(time.Now().Add(budget))
	io.Copy(io.Discard, up) // the worker has seen the cancel once it closes the proxy's connection

	admitted := 0
	for range workerStreams {
		c := dial()
		c.Write(key)
		select {
		case <-accepted:
			admitted++
		case <-closed(c):
		case <-time.After(budget):
			t.Fatal("a stream was neither refused nor joined")
		}
	}
	if admitted != workerStreams-1 {
		t.Fatalf("%d streams were let in beside one that had not stopped: want %d", admitted, workerStreams-1)
	}
}

func TestWorkerHoldsItsStreamsToTheRate(t *testing.T) {
	var mu sync.Mutex
	clock, slept := time.Unix(0, 0), time.Duration(0)
	const rate, sent = 1 << 20, 8 << 20
	pace := &pacer{rate: rate, now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}, sleep: func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		clock, slept = clock.Add(d), slept+d
	}}
	key := newKey()
	target, accepted := proxy(t)
	c := served(t, key, target, pace)()

	go func() {
		c.Write(key)
		toFrames(c, io.LimitReader(zeros{}, sent), nil)
	}()
	up := within(t, accepted, "stream at the proxy")
	up.SetDeadline(time.Now().Add(budget))
	if n, err := io.Copy(io.Discard, up); n != sent || err != nil {
		t.Fatalf("the proxy read %d bytes, %v: want %d", n, err, sent)
	}
	mu.Lock()
	defer mu.Unlock()
	if want := sent / rate * time.Second; slept < want-2*paceSlack || slept > want {
		t.Fatalf("carrying %d bytes at %d a second slept %v: want %v, less at most %v", sent, rate, slept, want, 2*paceSlack)
	}
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// hostileWorker, in the environment, names a signal: this binary as a worker then sends it to all of its uid, again and again.
const hostileWorker = "VSOCK_EGRESS_TEST_HOSTILE_WORKER"

// brokenReaper, in the environment, makes this binary as a reaper stop itself ("stops") or end having done nothing ("fails").
const brokenReaper = "VSOCK_EGRESS_TEST_BROKEN_REAPER"

// fullDisk, in the environment, is the most bytes a file may hold that this binary writes, as on a disk with no more room.
const fullDisk = "VSOCK_EGRESS_TEST_FULL_DISK"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") { // tests start this binary as its commands
		switch how := os.Getenv(brokenReaper); {
		case os.Args[1] == "reap" && how == "fails":
			os.Exit(1)
		case os.Args[1] == "reap" && how == "stops":
			syscall.Kill(os.Getpid(), syscall.SIGSTOP)
		}
		if signal, err := strconv.Atoi(os.Getenv(hostileWorker)); err == nil && os.Args[1] == "work" {
			os.WriteFile(filepath.Join(filepath.Dir(os.Args[5]), "signalling"), nil, 0o600) // beside the socket -vsock names
			// On eight threads: a reaper it could signal would not outrun them all.
			for range 7 {
				go func() {
					for {
						syscall.Kill(-1, syscall.Signal(signal))
					}
				}()
			}
			for {
				syscall.Kill(-1, syscall.Signal(signal))
			}
		}
		if most, err := strconv.ParseUint(os.Getenv(fullDisk), 10, 64); err == nil {
			syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: most, Max: most})
		}
		main()
		return
	}
	os.Exit(m.Run())
}
