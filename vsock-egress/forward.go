package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// forwarder is the sandbox's side. It reads nothing of what it carries and names no destination.
type forwarder struct {
	key     [keySize]byte // minted once for the pod: the node fetches it, and refuses a stream without it
	host    uint32        // the node's CID
	port    uint32        // the node's vsock port for streams
	slots   chan struct{} // one for each connection it carries
	queue   chan struct{} // one for each connection it carries or holds back
	wait    time.Duration // how long a connection is held back for a place
	connect func(cid, port uint32) (*os.File, error)

	names *names // with capture: the address each name the sandbox looked up was given
}

func newForwarder(host, port uint32) *forwarder {
	return &forwarder{host: host, port: port, slots: make(chan struct{}, maxStreams),
		queue: make(chan struct{}, maxStreams+maxWaiting), wait: handshakeWait, connect: vsockDial}
}

func forward(args []string) error {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:3128", "the address the sandbox's programs use as their HTTP proxy")
	keyFile := fs.String("key", "", "where the key is kept, in a directory only the forwarder can read")
	capture := fs.Bool("capture", false, "answer the sandbox's DNS and carry the connections that vsock-egress redirect sends here")
	own := fs.String("own", "", "with -capture: the pod's own names, with commas between, which lead to the pod itself")
	fs.Parse(args)
	os.Remove(*keyFile + readySuffix) // an earlier forwarder's
	f := newForwarder(hostCID, streamPort)
	if err := f.loadKey(*keyFile); err != nil {
		return err
	}
	if *capture {
		if err := f.capture(*keyFile+namesSuffix, strings.Split(*own, ",")); err != nil {
			return err
		}
	}
	keys, err := vsockListen(keyPort)
	if err != nil {
		return err
	}
	defer keys.f.Close()
	go f.serveKey(keys)
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*keyFile+readySuffix, nil, 0o600); err != nil {
		return err
	}
	return f.serve(l, f.proxied)
}

// capture starts the sandbox's resolver, and the port its redirected connections arrive at.
func (f *forwarder) capture(namesFile string, own []string) (err error) {
	if f.names, err = loadNames(namesFile, own); err != nil {
		return err
	}
	var plain net.ListenConfig
	plain.SetMultipathTCP(false) // Go listens with MPTCP unless told, and such a connection does not say where it was going
	redirected, err := plain.Listen(context.Background(), "tcp4", captureAddr)
	if err != nil {
		return err
	}
	queries, err := net.ListenPacket("udp4", captureAddr)
	if err != nil {
		return err
	}
	go func() { log.Fatal(f.names.resolve(queries)) }()
	go func() { log.Fatal(f.serve(redirected, f.captured)) }()
	return nil
}

// readySuffix names the file beside the key that is there while the forwarder listens on all of its ports.
const readySuffix = ".ready"

// ready is the forwarder's startup probe: the kubelet can reach no port of a pod with no network device.
func ready(args []string) error {
	fs := flag.NewFlagSet("ready", flag.ExitOnError)
	keyFile := fs.String("key", "", "where the forwarder keeps its key")
	fs.Parse(args)
	_, err := os.Stat(*keyFile + readySuffix)
	return err
}

// loadKey takes the key from file, minting it there if the file holds none: the worker fetches it once, so a restarted forwarder must come back with the same one.
func (f *forwarder) loadKey(file string) error {
	if kept, err := os.ReadFile(file); err == nil && len(kept) == keySize {
		copy(f.key[:], kept)
		return nil
	}
	rand.Read(f.key[:])
	return os.WriteFile(file, f.key[:], 0o600)
}

// serveKey gives the key to each peer the kernel says is the node: a process in this VM cannot claim that CID.
func (f *forwarder) serveKey(l *vsockListener) {
	for {
		c, peer, err := l.accept()
		if errors.Is(err, os.ErrClosed) {
			return
		}
		if err != nil { // a connection that ended before it was accepted, say: not the end of the key port
			log.Printf("key port: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if peer == f.host {
			c.Write(f.key[:])
		}
		c.Close()
	}
}

func (f *forwarder) serve(l net.Listener, carry func(*net.TCPConn)) error {
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return err
		}
		if err != nil { // out of descriptors, say: not the end of the forwarder
			log.Print(err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case f.queue <- struct{}{}:
			go func() {
				defer func() { <-f.queue }()
				carry(c.(*net.TCPConn))
			}()
		default:
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		}
	}
}

// proxied carries a connection to the proxy port: its program says where it wants to go.
func (f *forwarder) proxied(c *net.TCPConn) { f.stream(c, "") }

// stream carries one of the sandbox's connections to the node, on a vsock connection of its own.
func (f *forwarder) stream(c *net.TCPConn, target string) {
	// A client that closes a connection and opens the next is ahead of the node, where the old stream is still ending: refusing the new one broke clients that keep 64 busy.
	select {
	case f.slots <- struct{}{}:
		defer func() { <-f.slots }()
	case <-time.After(f.wait):
		c.SetLinger(0)
		c.Close()
		return
	}
	up, err := f.dial()
	if err != nil {
		log.Print(err)
		c.SetLinger(0)
		c.Close()
		return
	}
	if _, err := up.Write(f.key[:]); err != nil {
		log.Print(err)
		c.SetLinger(0)
		c.Close()
		up.Close()
		return
	}
	if target != "" && !tunnel(up, c, target) { // not logged: the sandbox chooses how many the proxy refuses
		c.SetLinger(0)
		c.Close()
		up.Close()
		return
	}
	join(up, c, nil)
}

// dial connects to the node's worker, waiting out one that is starting or being replaced: with none listening the connection is reset.
func (f *forwarder) dial() (*os.File, error) {
	for deadline := time.Now().Add(handshakeWait); ; time.Sleep(100 * time.Millisecond) {
		c, err := f.connect(f.host, f.port)
		if err == nil || !errors.Is(err, unix.ECONNRESET) || time.Now().After(deadline) {
			return c, err
		}
	}
}
