package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// worker is the node's side for one VM: it runs as the VM's uid inside the pod's network namespace, so the pod's own network policy governs what it dials.
type worker struct {
	vsock   string        // Firecracker's socket for the VM
	target  string        // the pod's egress proxy: every stream is joined to it, and nothing a guest sends names another
	pace    *pacer        // all of the sandbox's streams, both ways
	slots   chan struct{} // one for each open stream
	unkeyed chan struct{} // one for each connection whose key has not been checked yet
	keyWait time.Duration // how long a connection has to show its key

	mu      sync.Mutex
	key     []byte // the forwarder's
	fetched time.Time
	now     func() time.Time

	addr   atomic.Pointer[string] // the target's address, once looked up
	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)

	accepts *pacer       // new streams a second
	refused atomic.Int64 // streams turned away since the last report: without the key, or past the cap
	failed  atomic.Int64 // streams that did not reach the proxy since the last report
	keyless atomic.Int64 // fetches of the key that failed since the last report
}

// workerStreams is twice the forwarder's bound: a stream ends on the node a moment after it ends in the guest.
const workerStreams = 2 * maxStreams

// newStreams bounds the streams a worker takes in a second: past it Firecracker waits in its connect, so a guest that floods its worker holds up its own VM.
const newStreams = 2000

// proxyBuffer caps a stream's socket to the proxy each way, and the kernel accounts twice it, in memory every worker on the node shares; at half of it a download from another zone lost 5%.
const proxyBuffer = 512 << 10

func newWorker(vsock, target string, rate int) *worker {
	return &worker{vsock: vsock, target: target, pace: newPacer(rate), slots: make(chan struct{}, workerStreams), unkeyed: make(chan struct{}, workerStreams), keyWait: handshakeWait,
		now: time.Now, lookup: net.DefaultResolver.LookupNetIP, accepts: newPacer(newStreams)}
}

// report writes what went wrong since the last report as one line: a guest cannot fill the node's log a stream at a time.
func (w *worker) report() {
	if refused, failed, keyless := w.refused.Swap(0), w.failed.Swap(0), w.keyless.Swap(0); refused+failed+keyless > 0 {
		log.Printf("refused %d streams (no key, or more than %d open); %d did not reach the proxy; %d fetches of the key failed",
			refused, workerStreams, failed, keyless)
	}
}

func work(args []string) error {
	fs := flag.NewFlagSet("work", flag.ExitOnError)
	pod := fs.String("pod", "", "the pod, for the log")
	vsock := fs.String("vsock", "", "Firecracker's socket for the VM")
	target := fs.String("target", "", "host:port every stream is joined to")
	rate := fs.Int("rate", 0, "bytes a second, both ways together; 0 for no cap")
	fs.Parse(args)
	log.SetPrefix(*pod + ": ")
	// It waits on sockets, where more threads only wake each other, and one holds it to one of the node's CPUs.
	runtime.GOMAXPROCS(1)
	if os.Geteuid() == 0 {
		return errors.New("a worker runs as its VM's uid, never as root")
	}
	path := fmt.Sprintf("%s_%d", *vsock, streamPort) // where Firecracker takes the guest's connection to (host, streamPort)
	os.Remove(path)                                  // an earlier worker's
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	w := newWorker(*vsock, *target, *rate)
	go func() {
		for range time.Tick(time.Minute) {
			w.report()
		}
	}()
	return w.serve(l)
}

func (w *worker) serve(l net.Listener) error {
	for {
		w.accepts.wait(1)
		c, err := l.Accept()
		if err != nil {
			return err
		}
		select {
		case w.unkeyed <- struct{}{}:
			go w.stream(c)
		default: // a guest that floods the port with connections that show no key is held to these, as to its streams
			w.refused.Add(1)
			c.Close()
		}
	}
}

// stream joins one of the guest's connections to the proxy, if it opens with the forwarder's key.
func (w *worker) stream(c net.Conn) {
	defer c.Close()
	key := make([]byte, keySize)
	c.SetReadDeadline(time.Now().Add(w.keyWait))
	_, err := io.ReadFull(c, key)
	keyed := err == nil && w.holds(key)
	<-w.unkeyed
	if !keyed {
		w.refused.Add(1)
		return
	}
	select { // only now: a connection that sends no key holds no stream's place
	case w.slots <- struct{}{}:
		defer func() { <-w.slots }()
	default:
		w.refused.Add(1)
		return
	}
	c.SetReadDeadline(time.Time{})
	t, err := w.dial()
	if err != nil {
		if w.failed.Add(1) == 1 { // the first of each report says why
			log.Print(err)
		}
		return
	}
	join(c, t.(*net.TCPConn), w.pace)
}

// dial connects to the pod's proxy, whose address it keeps until a dial fails: a Service keeps its address, a pod that is replaced does not.
func (w *worker) dial() (net.Conn, error) {
	addr := w.addr.Load()
	if addr == nil { // under no lock: a lookup that hangs holds up its own stream alone
		host, port, err := net.SplitHostPort(w.target)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialWait)
		ips, err := w.lookup(ctx, "ip4", host)
		cancel()
		if err != nil {
			return nil, err
		}
		found := net.JoinHostPort(ips[0].String(), port)
		addr = &found
		w.addr.CompareAndSwap(nil, addr) // an answer that came meanwhile is the newer one
	}
	c, err := net.DialTimeout("tcp", *addr, dialWait)
	if err != nil {
		w.addr.CompareAndSwap(addr, nil)
		return nil, err
	}
	c.(*net.TCPConn).SetReadBuffer(proxyBuffer)
	c.(*net.TCPConn).SetWriteBuffer(proxyBuffer)
	return c, nil
}

// holds reports whether key is the forwarder's, which a worker fetches once, asking at most once a second: whoever holds the guest's key port later cannot give it another.
func (w *worker) holds(key []byte) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if now := w.now(); w.key == nil && now.Sub(w.fetched) >= time.Second {
		w.fetched = now
		fetched, err := fetchKey(w.vsock)
		if err != nil {
			if w.keyless.Add(1) == 1 { // the first of each report says why
				log.Print(err)
			}
			return false
		}
		w.key = fetched
	}
	return subtle.ConstantTimeCompare(key, w.key) == 1
}

func fetchKey(vsock string) ([]byte, error) {
	c, err := guestDial(vsock, keyPort)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	key := make([]byte, keySize)
	if _, err := io.ReadFull(c, key); err != nil {
		return nil, fmt.Errorf("the guest's key: %w", err)
	}
	return key, nil
}

// guestDial connects to a guest's vsock port as Firecracker's socket asks ("CONNECT port\n", answered "OK port\n"); the connection keeps a deadline of dialWait.
func guestDial(vsock string, port uint32) (net.Conn, error) {
	c, err := net.DialTimeout("unix", vsock, dialWait)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(dialWait))
	fmt.Fprintf(c, "CONNECT %d\n", port)
	reply := make([]byte, 0, 32)
	for b := make([]byte, 1); !bytes.HasSuffix(reply, []byte("\n")) && len(reply) < cap(reply); reply = append(reply, b[0]) {
		if _, err := c.Read(b); err != nil { // a byte at a time: what follows the line is the guest's
			c.Close()
			return nil, fmt.Errorf("guest vsock port %d: no answer from Firecracker: %w", port, err)
		}
	}
	if !bytes.HasPrefix(reply, []byte("OK ")) {
		c.Close()
		return nil, fmt.Errorf("guest vsock port %d: Firecracker answered %q", port, reply)
	}
	return c, nil
}
