package main

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime"
	"sync"
	"time"
)

// worker is the node's side for one VM. It runs as the VM's uid, with no capability, inside the pod's network
// namespace, so that the pod's own network policy governs what it dials.
type worker struct {
	vsock  string        // Firecracker's socket for the VM
	target string        // the pod's egress proxy: every stream is joined to it, and nothing a guest sends names another
	pace   *pacer        // all of the sandbox's streams, both ways
	slots  chan struct{} // one for each open stream

	mu      sync.Mutex
	key     []byte // the forwarder's
	fetched time.Time
}

func newWorker(vsock, target string, rate int) *worker {
	return &worker{vsock: vsock, target: target, pace: newPacer(rate), slots: make(chan struct{}, maxStreams)}
}

func work(args []string) error {
	fs := flag.NewFlagSet("work", flag.ExitOnError)
	pod := fs.String("pod", "", "the pod, for the log")
	vsock := fs.String("vsock", "", "Firecracker's socket for the VM")
	target := fs.String("target", "", "ip:port every stream is joined to")
	rate := fs.Int("rate", 0, "bytes a second, both ways together; 0 for no cap")
	fs.Parse(args)
	log.SetPrefix(*pod + ": ")
	runtime.GOMAXPROCS(1) // one sandbox's streams take at most one of the node's CPUs
	if os.Geteuid() == 0 {
		return errors.New("a worker runs as its VM's uid, never as root")
	}
	path := fmt.Sprintf("%s_%d", *vsock, streamPort) // where Firecracker takes the guest's connection to (host, streamPort)
	os.Remove(path)                                  // an earlier worker's
	l, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	go func() { // the launcher ends a worker by closing its stdin, and so does the launcher's own end
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}()
	return newWorker(*vsock, *target, *rate).serve(l)
}

func (w *worker) serve(l net.Listener) error {
	for {
		c, err := l.Accept()
		if err != nil {
			return err
		}
		select {
		case w.slots <- struct{}{}:
			go func() {
				defer func() { <-w.slots }()
				w.stream(c)
			}()
		default:
			log.Printf("refused a stream: %d are open", maxStreams)
			c.Close()
		}
	}
}

// stream joins one of the guest's connections to the proxy, if it opens with the forwarder's key.
func (w *worker) stream(c net.Conn) {
	defer c.Close()
	key := make([]byte, keySize)
	c.SetReadDeadline(time.Now().Add(handshakeWait))
	if _, err := io.ReadFull(c, key); err != nil || !w.holds(key) {
		log.Print("refused a stream that did not open with the sandbox's key")
		return
	}
	c.SetReadDeadline(time.Time{})
	t, err := net.DialTimeout("tcp", w.target, dialWait)
	if err != nil {
		log.Print(err)
		return
	}
	join(c, t.(*net.TCPConn), w.pace)
}

// holds reports whether key is the forwarder's. A forwarder that restarted has a new one, so a key that does
// not match is checked against the guest's once more, at most once a second.
func (w *worker) holds(key []byte) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if subtle.ConstantTimeCompare(key, w.key) == 1 {
		return true
	}
	if time.Since(w.fetched) < time.Second {
		return false
	}
	w.fetched = time.Now()
	fresh, err := fetchKey(w.vsock)
	if err != nil {
		log.Print(err)
		return false
	}
	w.key = fresh
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

// guestDial connects to a vsock port that a guest process listens on, as Firecracker's socket asks:
// "CONNECT port\n", answered "OK port\n". The connection keeps a deadline of dialWait.
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
