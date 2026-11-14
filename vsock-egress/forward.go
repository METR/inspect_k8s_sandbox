package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"log"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// forwarder is the sandbox's side. It reads nothing of what it carries and names no destination.
type forwarder struct {
	key  [keySize]byte // minted at start and kept in memory: the node fetches it, and refuses a stream without it
	host uint32        // the node's CID
	port uint32        // the node's vsock port for streams
}

func forward(args []string) error {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	addr := fs.String("listen", "127.0.0.1:3128", "the address the sandbox's programs use as their HTTP proxy")
	fs.Parse(args)
	runtime.GOMAXPROCS(1) // a relay waits on sockets: more threads only wake each other, on the sandbox's own CPUs
	f := &forwarder{host: hostCID, port: streamPort}
	rand.Read(f.key[:])
	keys, err := vsockListen(keyPort)
	if err != nil {
		return err
	}
	go f.serveKey(keys)
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	return f.serve(l)
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
		go f.stream(c.(*net.TCPConn))
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
