package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// firecracker stands in for a VM's vsock socket on the node: it answers CONNECT for a guest port with what a
// guest process listening there would say first.
func firecracker(t *testing.T, says map[uint32]string) (vsock string) {
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
			if say, ok := says[port]; ok { // with no listener in the guest, Firecracker closes without a word
				fmt.Fprintf(c, "OK 1073741824\n%s", say)
			}
			c.Close()
		}
	}()
	return vsock
}

// proxy is a TCP server that hands over each connection it accepts.
func proxy(t *testing.T) (address string, accepted chan net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
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
	streams := fmt.Sprintf("%s_%d", w.vsock, streamPort)
	l, err := net.Listen("unix", streams)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go w.serve(l)
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

func newKey() []byte {
	key := make([]byte, keySize)
	rand.Read(key)
	return key
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

func TestRefusedStreamsAreCountedNotLoggedOneByOne(t *testing.T) {
	var out logged
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
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
	// Other tests' workers may still be writing to the log: only lines about refusals count.
	out.Lock()
	lines := strings.Count(out.String(), "refused")
	out.Unlock()
	if lines != 0 {
		t.Fatalf("%d lines about refused streams were written as they came", lines)
	}
	w.report()
	out.Lock()
	defer out.Unlock()
	if want := fmt.Sprintf("refused %d streams", refused); !strings.Contains(out.String(), want) {
		t.Fatalf("the report is %q, want %q in it", out.String(), want)
	}
}

func TestNewStreamsAreTakenAtABoundedRate(t *testing.T) {
	var mu sync.Mutex
	clock, slept := time.Unix(0, 0), time.Duration(0)
	const rate, streams = 10, 100
	target, _ := proxy(t)
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(newKey())}), target, 0)
	w.accepts = &pacer{rate: rate, now: func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return clock
	}, sleep: func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		clock, slept = clock.Add(d), slept+d
	}}
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
	if least := (streams/rate - 1) * time.Second; slept < least {
		t.Fatalf("taking %d streams at %d a second waited %v: want at least %v", streams, rate, slept, least)
	}
}

func TestKeyIsFetchedOnceForAWorker(t *testing.T) {
	key, other := newKey(), newKey()
	target, accepted := proxy(t)
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), target, 0)
	dial := serve(t, w)
	dial().Write(key)
	select {
	case <-accepted:
	case <-time.After(budget):
		t.Fatal("the forwarder's stream reached nothing")
	}

	// The forwarder has died and a workload process holds the guest's key port, with a key of its own.
	squatted := firecracker(t, map[uint32]string{keyPort: string(other)})
	w.mu.Lock()
	w.vsock = squatted
	w.mu.Unlock()
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
	key := newKey()
	target, accepted := proxy(t)
	_, port, _ := net.SplitHostPort(target)
	// The proxy's pod was replaced: its name first gives an address where nothing listens any more.
	answers := []string{"127.0.0.2", "127.0.0.1"}
	w := newWorker(firecracker(t, map[uint32]string{keyPort: string(key)}), net.JoinHostPort("proxy.test", port), 0)
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

func TestConnectionsThatSendNoKeyTakeNoStreamsPlace(t *testing.T) {
	key := newKey()
	target, accepted := proxy(t)
	dial := served(t, key, target, nil)

	for range workerStreams { // a workload process dials and says nothing
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
	up := <-accepted
	up.Write([]byte("reply"))
	<-asleep
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
	up := <-accepted
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

// deafWorker, in the environment, makes this binary a worker that ignores its stdin closing.
const deafWorker = "VSOCK_EGRESS_TEST_DEAF_WORKER"

// hostileWorker, in the environment, names a signal: this binary as a worker then sends it to all of its uid, again and again.
const hostileWorker = "VSOCK_EGRESS_TEST_HOSTILE_WORKER"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && (os.Args[1] == "work" || os.Args[1] == "reap") { // the launcher's test starts this binary as its children
		if signal, err := strconv.Atoi(os.Getenv(hostileWorker)); err == nil && os.Args[1] == "work" {
			os.WriteFile(filepath.Join(filepath.Dir(os.Args[5]), "signalling"), nil, 0o600) // beside the socket -vsock names
			for {
				syscall.Kill(-1, syscall.Signal(signal))
			}
		}
		for os.Args[1] == "work" && os.Getenv(deafWorker) != "" {
			time.Sleep(time.Hour)
		}
		main()
		return
	}
	os.Exit(m.Run())
}
