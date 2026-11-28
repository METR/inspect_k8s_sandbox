package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// worker is the node's side for one VM: it runs as the VM's uid inside the pod's network namespace, so the pod's own network policy governs what it dials and who reaches it.
type worker struct {
	vsock    string                 // Firecracker's socket for the VM
	proxy    *target                // the pod's egress proxy: every proxy stream is joined to it
	siblings map[netip.Addr]*target // each sibling's worker, by the address the sibling has in the sandbox: nothing a guest sends names another
	ports    map[uint16]bool        // the ports of the pod its siblings may reach; nil for every port
	pace     *pacer                 // all of the sandbox's streams, both ways
	slots    chan struct{}          // one for each open stream
	unkeyed  chan struct{}          // one for each connection that has not said what it wants yet: the key, or a sibling's port
	arriving chan struct{}          // one for each connection its siblings have to it: they leave the pod's own streams half the places
	keyWait  time.Duration          // how long a connection has to say what it wants
	stall    time.Duration          // how long the far end may leave a write to it, or the end of them, waiting

	mu      sync.Mutex
	key     []byte // the forwarder's
	fetched time.Time
	now     func() time.Time

	lookup func(ctx context.Context, network, host string) ([]netip.Addr, error)

	accepts   *pacer       // new streams a second
	refused   atomic.Int64 // streams turned away since the last report: without the key, to no sibling, to a port the pod does not serve, or past the cap
	failed    atomic.Int64 // streams that did not reach the proxy since the last report
	keyless   atomic.Int64 // fetches of the key that failed since the last report
	unreached atomic.Int64 // streams that did not reach a sibling's worker since the last report
	unentered atomic.Int64 // siblings' connections the guest did not take since the last report
}

// target is a place the worker dials for its sandbox, as host:port.
type target struct {
	name       string
	fresh      time.Duration             // how long its address is used before its name is asked again: 0 for until a dial fails
	addr       atomic.Pointer[string]    // its address, once looked up
	asked      atomic.Pointer[time.Time] // when that was: a Time, whose monotonic reading no step of the node's clock moves
	unresolved atomic.Pointer[failedLookup]
}

// siblingFresh is the cluster DNS's own time to live for a Service: a sibling's names its pod, whose address another sibling's pod can take once it is replaced, and that one's worker would answer.
const siblingFresh = 5 * time.Second

// workerStreams is twice the forwarder's bound: a stream ends on the node a moment after it ends in the guest, and the pod's siblings may hold half of them.
const workerStreams = 2 * maxStreams

// newStreams bounds the streams a worker takes in a second: past it Firecracker waits in its connect, so a guest that floods its worker holds up its own VM.
const newStreams = 2000

// failedLookup is the target's last lookup that failed, and when: for a second after, streams fail as it did.
type failedLookup struct {
	err error
	at  time.Time
}

// endedWait is how long a stream whose dial failed is given to show that the guest had already ended it.
const endedWait = 10 * time.Millisecond

// stallWait ends a stream whose proxy, or whose client in the sandbox, has stopped reading: it would hold its slot and its place for as long as that peer kept the connection.
const stallWait = 5 * time.Minute

// proxyBuffer caps a stream's socket to the proxy each way, and the kernel accounts twice it, in memory every worker on the node shares; at half of it a download from another zone lost 5%.
const proxyBuffer = 512 << 10

func newWorker(vsock, proxy string, rate int) *worker {
	return &worker{vsock: vsock, proxy: &target{name: proxy}, siblings: map[netip.Addr]*target{}, pace: newPacer(rate), slots: make(chan struct{}, workerStreams), unkeyed: make(chan struct{}, workerStreams), arriving: make(chan struct{}, maxStreams), keyWait: handshakeWait, stall: stallWait,
		now: time.Now, lookup: net.DefaultResolver.LookupNetIP, accepts: newPacer(newStreams)}
}

// annotated takes what the launcher read from the pod's annotations: address=host for each sibling, and the ports the siblings may reach.
func (w *worker) annotated(siblings, ports string) error {
	for _, sibling := range strings.FieldsFunc(siblings, func(r rune) bool { return r == ',' }) {
		at, host, _ := strings.Cut(sibling, "=")
		addr, err := netip.ParseAddr(at)
		if err != nil {
			return err
		}
		w.siblings[addr] = &target{name: net.JoinHostPort(host, strconv.Itoa(relayPort)), fresh: siblingFresh}
	}
	if ports == "*" {
		return nil
	}
	w.ports = map[uint16]bool{}
	for _, port := range strings.FieldsFunc(ports, func(r rune) bool { return r == ',' }) {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return err
		}
		w.ports[uint16(n)] = true
	}
	return nil
}

// report writes what went wrong since the last report, a line for each kind: a guest cannot fill the node's log a stream at a time.
func (w *worker) report() {
	if refused := w.refused.Swap(0); refused > 0 {
		log.Printf("streams_refused: %d since the last report", refused)
	}
	if failed := w.failed.Swap(0); failed > 0 {
		log.Printf("proxy_unreached: %d streams since the last report", failed)
	}
	if keyless := w.keyless.Swap(0); keyless > 0 {
		log.Printf("key_unfetched: %d fetches since the last report", keyless)
	}
	if unreached := w.unreached.Swap(0); unreached > 0 {
		log.Printf("sibling_unreached: %d streams since the last report", unreached)
	}
	if unentered := w.unentered.Swap(0); unentered > 0 {
		log.Printf("guest_unreached: %d connections since the last report", unentered)
	}
}

// refuse counts a stream turned away; the first of each report is written at once.
func (w *worker) refuse() {
	if w.refused.Add(1) == 1 {
		log.Printf("streams_refused: a stream with no key, to no proxy or sibling of the pod's or no port it serves, or past the %d open, of which its siblings may hold %d", workerStreams, maxStreams)
	}
}

func work(args []string) error {
	fs := flag.NewFlagSet("work", flag.ExitOnError)
	pod := fs.String("pod", "", "the pod, for the log")
	vsock := fs.String("vsock", "", "Firecracker's socket for the VM")
	target := fs.String("target", "", "host:port every proxy stream is joined to")
	siblings := fs.String("siblings", "", "address=host for each sibling service of the pod, with commas between")
	ports := fs.String("ports", "", "the ports of the pod its siblings may reach: *, or a list with commas between")
	rate := fs.Int("rate", 0, "bytes a second, both ways together; 0 for no cap")
	fs.Parse(args)
	log.SetPrefix(*pod + ": ")
	// It waits on sockets, where more threads only wake each other, and one holds it to one of the node's CPUs.
	runtime.GOMAXPROCS(1)
	if os.Geteuid() == 0 {
		return errors.New("a worker runs as its VM's uid, never as root")
	}
	// Out of memory, the kernel then ends a worker before the launcher, whose end would end every worker: the README says when.
	if err := os.WriteFile("/proc/self/oom_score_adj", []byte("1000"), 0); err != nil {
		return err
	}
	w := newWorker(*vsock, *target, *rate)
	if err := w.annotated(*siblings, *ports); err != nil {
		return err
	}
	ended := make(chan error)
	// Before the sockets its forwarder's readiness waits for: a pod that is ready takes its siblings' connections.
	if *ports != "" {
		l, err := taking(fmt.Sprintf(":%d", relayPort))
		if err != nil {
			return err
		}
		go func() { ended <- w.serve(l, w.arrive) }()
	}
	for port, carry := range map[int]func(net.Conn){streamPort: w.proxied, siblingPort: w.sibling} {
		path := fmt.Sprintf("%s_%d", *vsock, port) // where Firecracker takes the guest's connection to (host, port)
		os.Remove(path)                            // an earlier worker's
		l, err := net.Listen("unix", path)
		if err != nil {
			return err
		}
		go func() { ended <- w.serve(l, carry) }()
	}
	go func() {
		for range time.Tick(time.Minute) {
			w.report()
		}
	}()
	return <-ended
}

// taking listens at a port of the pod's for the connections made to it, and holds no more than maxStreams it has not accepted: the kernel keeps what each has sent, charged to no pod, and its own bound is 4096.
func taking(addr string) (net.Listener, error) {
	l, err := listen(addr, proxyBuffer)
	if err != nil {
		return nil, err
	}
	raw, err := l.(*net.TCPListener).SyscallConn()
	if err == nil {
		if failed := raw.Control(func(fd uintptr) { err = syscall.Listen(int(fd), maxStreams) }); failed != nil {
			err = failed
		}
	}
	if err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// serve gives each connection to l to carry, which says what it wants within keyWait.
func (w *worker) serve(l net.Listener, carry func(net.Conn)) error {
	for {
		w.accepts.wait(1)
		c, err := l.Accept()
		if err != nil {
			return err
		}
		select {
		case w.unkeyed <- struct{}{}:
			go carry(c)
		default: // whoever floods a port with connections that say nothing is held to these, as to its streams
			w.refuse()
			c.Close()
		}
	}
}

// proxied joins one of the guest's connections to the proxy, if it opens with the forwarder's key.
func (w *worker) proxied(c net.Conn) { w.stream(c, 0) }

// sibling joins one to the worker of the sibling whose address follows the key, and tells that worker the port.
func (w *worker) sibling(c net.Conn) { w.stream(c, net.IPv4len+2) }

// stream reads the key and the asked bytes that say where one of the guest's connections was going, and joins it to there.
func (w *worker) stream(c net.Conn, asked int) {
	defer c.Close()
	hello := make([]byte, keySize+asked)
	c.SetReadDeadline(time.Now().Add(w.keyWait))
	_, err := io.ReadFull(c, hello)
	keyed := err == nil && w.holds(hello[:keySize])
	<-w.unkeyed
	to, port, unreached, word := w.proxy, []byte(nil), &w.failed, "proxy_unreached"
	if asked > 0 { // the address the connection was going to, then its port, which the sibling's worker reads as it is
		to, port, unreached, word = w.siblings[netip.AddrFrom4([4]byte(hello[keySize:]))], hello[keySize+4:], &w.unreached, "sibling_unreached"
	}
	if !keyed || to == nil {
		w.refuse()
		return
	}
	select { // only now: a connection that sends no key holds no stream's place
	case w.slots <- struct{}{}:
		defer func() { <-w.slots }()
	default:
		w.refuse()
		return
	}
	t, err := w.dial(to)
	if err == nil && asked > 0 {
		if _, err = t.Write(port); err != nil {
			t.Close()
		}
	}
	if err != nil {
		// The forwarder's startup probe ends its stream at once: one that came before the proxy is no stream that failed.
		c.SetReadDeadline(time.Now().Add(endedWait))
		if _, ended := c.Read(make([]byte, 1)); ended == io.EOF {
			return
		}
		if to.name == "" { // its pod names no proxy: the sandbox sent this itself, and no proxy failed
			w.refuse()
			return
		}
		if unreached.Add(1) == 1 { // the first of each report says why
			log.Printf("%s: %v", word, err)
		}
		return
	}
	join(c, t.(*net.TCPConn), w.pace, w.stall)
}

// arrive hands a connection from the worker of one of the pod's siblings to the forwarder, to the port it asks for, once what holds the guest's inbound port has shown the forwarder's key.
func (w *worker) arrive(c net.Conn) {
	tcp := c.(*net.TCPConn)
	defer tcp.Close()
	tcp.SetLinger(0) // until it is joined, a connection that ends here ends as one to a closed port does
	select {
	case w.arriving <- struct{}{}:
		defer func() { <-w.arriving }()
	default:
		<-w.unkeyed
		w.refuse()
		return
	}
	port := make([]byte, 2)
	tcp.SetReadDeadline(time.Now().Add(w.keyWait))
	_, err := io.ReadFull(tcp, port)
	<-w.unkeyed
	if err != nil || w.ports != nil && !w.ports[binary.BigEndian.Uint16(port)] {
		w.refuse()
		return
	}
	select {
	case w.slots <- struct{}{}:
		defer func() { <-w.slots }()
	default:
		w.refuse()
		return
	}
	tcp.SetReadBuffer(proxyBuffer)
	tcp.SetWriteBuffer(proxyBuffer)
	g, err := guestDial(w.vsock, inboundPort)
	if err == nil {
		key := make([]byte, keySize)
		if _, err = io.ReadFull(g, key); err == nil && !w.holds(key) {
			err = errors.New("what holds the guest's inbound port did not show the forwarder's key")
		}
		if err == nil {
			_, err = g.Write(port)
		}
		if err != nil {
			g.Close()
		}
	}
	if err != nil {
		if w.unentered.Add(1) == 1 { // the first of each report says why
			log.Printf("guest_unreached: %v", err)
		}
		return
	}
	join(g, tcp, w.pace, w.stall)
}

// dial connects to t. A failed dial has its address looked up again, once a second at most: a replaced pod has another, and neither a target that is down nor a name that does not resolve may cost a lookup a stream.
func (w *worker) dial(t *target) (net.Conn, error) {
	addr := t.addr.Load()
	if addr != nil && t.fresh > 0 && w.now().Sub(*t.asked.Load()) >= t.fresh {
		t.addr.CompareAndSwap(addr, nil)
		addr = nil
	}
	if addr == nil { // under no lock: streams that ask during a lookup share it, each for dialWait at most
		host, port, err := net.SplitHostPort(t.name)
		if err != nil {
			return nil, err
		}
		if last := t.unresolved.Load(); last != nil && w.now().Sub(last.at) < time.Second {
			return nil, last.err
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialWait)
		ips, err := w.lookup(ctx, "ip4", host)
		cancel()
		if err != nil {
			t.unresolved.Store(&failedLookup{err, w.now()})
			return nil, err
		}
		found := net.JoinHostPort(ips[0].String(), port)
		addr = &found
		asked := w.now()
		t.asked.Store(&asked)
		t.addr.CompareAndSwap(nil, addr) // an answer that came meanwhile is the newer one
	}
	c, err := net.DialTimeout("tcp", *addr, dialWait)
	if err != nil {
		if w.now().Sub(*t.asked.Load()) >= time.Second {
			t.addr.CompareAndSwap(addr, nil)
		}
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
				log.Printf("key_unfetched: %v", err)
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
