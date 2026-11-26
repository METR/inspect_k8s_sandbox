package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// forwarder is the sandbox's side. It reads nothing of what it carries and names no Service.
type forwarder struct {
	key      [keySize]byte // minted once for the pod: the node fetches it, and refuses a stream without it
	host     uint32        // the node's CID
	port     uint32        // the node's vsock port for proxy streams
	siblings uint32        // and for a sibling's
	names    *names        // the names a captured sandbox has looked up
	slots    chan struct{} // one for each connection it carries
	queue    chan struct{} // one for each connection it carries or holds back
	wait     time.Duration // how long a connection is held back for a place
	connect  func(cid, port uint32) (*os.File, error)
}

func newForwarder(host, port uint32) *forwarder {
	return &forwarder{host: host, port: port, siblings: siblingPort, names: newNames(""), slots: make(chan struct{}, maxStreams),
		queue: make(chan struct{}, maxStreams+maxWaiting), wait: handshakeWait, connect: vsockDial}
}

func forward(args []string) error {
	fs := flag.NewFlagSet("forward", flag.ExitOnError)
	addr := fs.String("listen", fmt.Sprintf("127.0.0.1:%d", forwarderPort), "the address the sandbox's programs use as their HTTP proxy")
	keyFile := fs.String("key", "", "where the key is kept, in a directory only the forwarder can read")
	fs.Parse(args)
	f := newForwarder(hostCID, streamPort)
	keys, err := vsockListen(keyPort) // first: one forwarder alone can hold this port, and a second ends here having touched nothing of the first's
	if err != nil {
		return err
	}
	defer keys.f.Close()
	os.Remove(*keyFile + readySuffix) // an earlier forwarder's
	if err := f.loadKey(*keyFile); err != nil {
		return err
	}
	go f.serveKey(keys)
	l, err := listen(*addr, clientBuffer)
	if err != nil {
		return err
	}
	// Where capture sends the sandbox's lookups: the same port, so that no pod loses another to it.
	lookups, err := net.ListenPacket("udp", *addr)
	if err != nil {
		return err
	}
	f.names = newNames(*keyFile + ".names") // beside the key, which outlives a restart too
	go f.names.serve(lookups)
	arrivals, err := vsockListen(inboundPort)
	if err != nil {
		return err
	}
	defer arrivals.f.Close()
	go f.fromNode(arrivals, func(c *os.File) { go f.arrive(c) })
	if err := os.WriteFile(*keyFile+readySuffix, nil, 0o600); err != nil {
		return err
	}
	return f.serve(l)
}

// readySuffix names the file beside the key that is there while the forwarder listens on all of its ports.
const readySuffix = ".ready"

// ready is the forwarder's startup probe: the kubelet can reach no port of a pod with no network device.
func ready(args []string) error {
	fs := flag.NewFlagSet("ready", flag.ExitOnError)
	keyFile := fs.String("key", "", "where the forwarder keeps its key")
	fs.Parse(args)
	return newForwarder(hostCID, streamPort).ready(*keyFile)
}

// ready passes once the forwarder listens and its worker does: with no worker for its VM, Firecracker resets the connection.
func (f *forwarder) ready(keyFile string) error {
	if _, err := os.Stat(keyFile + readySuffix); err != nil {
		return err
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	c, err := f.connect(f.host, f.port)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(key) // a stream that opens with the key and ends: every worker takes that
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

// fromNode calls each with every connection to l that the kernel says is the node's: a process in this VM cannot claim that CID.
func (f *forwarder) fromNode(l *vsockListener, each func(*os.File)) {
	for {
		c, peer, err := l.accept()
		if errors.Is(err, os.ErrClosed) {
			return
		}
		if err != nil { // a connection that ended before it was accepted, say: not the end of the port
			log.Printf("vsock port: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if peer != f.host {
			c.Close()
			continue
		}
		each(c)
	}
}

// serveKey gives the key to the node.
func (f *forwarder) serveKey(l *vsockListener) {
	f.fromNode(l, func(c *os.File) {
		c.Write(f.key[:])
		c.Close()
	})
}

// arrive carries a connection the node opened, for one made to the pod, to the port it names, after showing the key: whoever else held this vsock port could not.
func (f *forwarder) arrive(c *os.File) {
	port := make([]byte, 2)
	c.SetDeadline(time.Now().Add(handshakeWait))
	_, err := c.Write(f.key[:])
	if err == nil {
		_, err = io.ReadFull(c, port)
	}
	var t net.Conn
	if err == nil {
		t, err = net.DialTimeout("tcp", netip.AddrPortFrom(deliverTo, binary.BigEndian.Uint16(port)).String(), dialWait)
	}
	if err != nil { // no server on that port, say: the node resets the sibling's connection
		c.Close()
		return
	}
	c.SetDeadline(time.Time{})
	t.(*net.TCPConn).SetReadBuffer(clientBuffer)
	t.(*net.TCPConn).SetWriteBuffer(clientBuffer)
	join(c, t.(*net.TCPConn), nil, stallWait)
}

// listen takes a TCP port where every connection is born with its receive buffer held at half of buffer, the size the kernel starts it with: left alone until its stream runs, a client's small segments grow it to the kernel's maximum, and the listener is charged for it all as it accepts.
func listen(addr string, buffer int) (net.Listener, error) {
	held := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) { unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, buffer/2) })
	}}
	held.SetMultipathTCP(false) // Go listens for it unasked: a multipath connection's subflows have buffers of their own, which nothing set on the connection bounds, and it does not say where redirect found it going
	return held.Listen(context.Background(), "tcp", addr)
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
		case f.queue <- struct{}{}:
			go func() {
				defer func() { <-f.queue }()
				f.stream(c.(*net.TCPConn))
			}()
		default:
			c.(*net.TCPConn).SetLinger(0)
			c.Close()
		}
	}
}

// clientBuffer caps a stream's socket to its client each way, and the kernel accounts twice it: it bounds what the streams a guest stalls hold, under the forwarder's memory limit in the chart, and is smaller than the worker's proxyBuffer because loopback needs no more.
const clientBuffer = 128 << 10

// stream carries one of the sandbox's connections to the node on a vsock connection of its own: to the sibling redirect found it going to, named after the key, or else to the proxy, which is asked for wherever capture found it going.
func (f *forwarder) stream(c *net.TCPConn) {
	port, asked, captured := f.port, []byte(nil), ""
	if to, err := originalDst(c); err == nil {
		switch name := f.names.named(to.Addr()); {
		case siblingRange.Contains(to.Addr()):
			port, asked = f.siblings, binary.BigEndian.AppendUint16(to.Addr().AsSlice(), to.Port())
		case to == resolver:
			f.names.converse(c)
			return
		case name != "":
			captured = net.JoinHostPort(name, strconv.Itoa(int(to.Port())))
		case nameRange.Contains(to.Addr()): // an address this forwarder gave no name: one before it did
			c.SetLinger(0)
			c.Close()
			return
		case !to.Addr().IsLoopback(): // not a program that came to the proxy itself: an address written out
			captured = to.String()
		}
	}
	// A client that closes a connection and opens the next is ahead of the node, where the old stream is still ending: refusing the new one broke clients that keep 64 busy.
	select {
	case f.slots <- struct{}{}:
		defer func() { <-f.slots }()
	case <-time.After(f.wait):
		c.SetLinger(0)
		c.Close()
		return
	}
	// Only now the whole of it: the 448 that wait hold the half their listener gave them.
	c.SetReadBuffer(clientBuffer)
	c.SetWriteBuffer(clientBuffer)
	up, err := f.dial(port)
	if err != nil {
		log.Print(err)
		c.SetLinger(0)
		c.Close()
		return
	}
	_, err = up.Write(append(f.key[:], asked...))
	if err != nil {
		log.Print(err)
	} else if captured != "" {
		err = tunnel(up, c, captured) // the proxy's own record says what it refused: a line here for each would be the sandbox's to write at will
	}
	if err != nil {
		c.SetLinger(0)
		c.Close()
		up.Close()
		return
	}
	join(up, c, nil, stallWait)
}

// tunnel asks the proxy at the far end of up for target, as a program that read the proxy variables would, and gives c what follows the proxy's answer.
func tunnel(up *os.File, c *net.TCPConn, target string) error {
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n"
	up.SetDeadline(time.Now().Add(handshakeWait))
	defer up.SetDeadline(time.Time{})
	if _, err := up.Write(append(binary.BigEndian.AppendUint32(nil, uint32(len(request))), request...)); err != nil {
		return err
	}
	var answer []byte
	for !bytes.Contains(answer, []byte("\r\n\r\n")) {
		length := make([]byte, 4)
		if _, err := io.ReadFull(up, length); err != nil {
			return err
		}
		size := int(binary.BigEndian.Uint32(length))
		// What follows the headers in their last frame is the origin's, and may fill it.
		if size == 0 || size > maxFrame || len(answer) > maxFrame {
			return fmt.Errorf("the proxy's answer to CONNECT %s ended, or ran past %d bytes, with no end of its headers", target, maxFrame)
		}
		answer = append(answer, make([]byte, size)...)
		if _, err := io.ReadFull(up, answer[len(answer)-size:]); err != nil {
			return err
		}
	}
	head, rest, _ := bytes.Cut(answer, []byte("\r\n\r\n"))
	if status := bytes.Fields(head); len(status) < 2 || string(status[1]) != "200" {
		line, _, _ := bytes.Cut(head, []byte("\r\n"))
		return fmt.Errorf("CONNECT %s: the proxy answered %q", target, line)
	}
	_, err := c.Write(rest)
	return err
}

// dial connects to the node's worker, waiting out one that is starting or being replaced: with none listening the connection is reset.
func (f *forwarder) dial(port uint32) (*os.File, error) {
	for deadline := time.Now().Add(handshakeWait); ; time.Sleep(100 * time.Millisecond) {
		c, err := f.connect(f.host, port)
		if err == nil || !errors.Is(err, unix.ECONNRESET) || time.Now().After(deadline) {
			return c, err
		}
	}
}
