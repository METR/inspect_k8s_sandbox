package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// forwarder is the sandbox's side. It reads nothing of what it carries and names no destination.
type forwarder struct {
	key   [keySize]byte // minted once for the pod: the node fetches it, and refuses a stream without it
	host  uint32        // the node's CID
	port  uint32        // the node's vsock port for streams
	slots chan struct{} // one for each connection it carries
}

func newForwarder(host, port uint32) *forwarder {
	return &forwarder{host: host, port: port, slots: make(chan struct{}, maxStreams)}
}

func forward(args []string) error {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:3128", "the address the sandbox's programs use as their HTTP proxy")
	keyFile := fs.String("key", "", "where the key is kept, in a directory only the forwarder can read")
	fs.Parse(args)
	os.Remove(*keyFile + readySuffix) // an earlier forwarder's
	f := newForwarder(hostCID, streamPort)
	if err := f.loadKey(*keyFile); err != nil {
		return err
	}
	keys, err := vsockListen(keyPort)
	if err != nil {
		return err
	}
	go f.serveKey(keys)
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*keyFile+readySuffix, nil, 0o600); err != nil {
		return err
	}
	return f.serve(l)
}

// readySuffix names the file beside the key that is there while the forwarder listens on both of its ports.
const readySuffix = ".ready"

// ready is the forwarder's startup probe: the kubelet can reach no port of a pod with no network device.
func ready(args []string) error {
	fs := flag.NewFlagSet("ready", flag.ExitOnError)
	keyFile := fs.String("key", "", "where the forwarder keeps its key")
	fs.Parse(args)
	_, err := os.Stat(*keyFile + readySuffix)
	return err
}

// loadKey takes the key from file, minting it there first if the file holds none: the worker fetches the
// key once, so a forwarder that is restarted must come back with the same one.
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

func (f *forwarder) serve(l net.Listener) error {
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
		case f.slots <- struct{}{}:
			go func() {
				defer func() { <-f.slots }()
				f.stream(c.(*net.TCPConn))
			}()
		default: // the worker joins no more: the rest would each hold a thread while its vsock connection is made
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		}
	}
}

// stream carries one of the sandbox's connections to the node, on a vsock connection of its own.
func (f *forwarder) stream(c *net.TCPConn) {
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
	join(up, c, nil)
}

// dial connects to the node's worker. With no worker listening the connection is reset, so this waits out
// one that is starting or being replaced.
func (f *forwarder) dial() (*os.File, error) {
	for deadline := time.Now().Add(handshakeWait); ; time.Sleep(100 * time.Millisecond) {
		c, err := vsockDial(f.host, f.port)
		if err == nil || !errors.Is(err, unix.ECONNRESET) || time.Now().After(deadline) {
			return c, err
		}
	}
}
