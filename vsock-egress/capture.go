package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

// captureRange is set aside for benchmarks (RFC 2544), so no host a sandbox may reach has an address in it.
var captureRange = netip.MustParsePrefix("198.18.0.0/15")

const (
	maxNames    = 1 << 14 // names a pod can look up in its life: each keeps its address, and the next gets no answer
	nameSeconds = 30      // how long a program may keep an answer
	namesSuffix = ".names"
	hostLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."
)

// names gives each host name an address in captureRange and finds the name again for a connection to it.
type names struct {
	own    map[string]bool // the pod's own names, which lead to the pod itself
	mu     sync.Mutex
	byName map[string]int
	list   []string // list[i] has the address i+1 places into captureRange
	kept   *os.File // every name in order: a forwarder that is restarted gives each the address it had
}

func loadNames(file string, own []string) (*names, error) {
	n := &names{own: map[string]bool{"localhost": true}, byName: map[string]int{}}
	for _, name := range own {
		n.own[strings.ToLower(strings.TrimSuffix(name, "."))] = true
	}
	kept, err := os.ReadFile(file)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	kept = kept[:bytes.LastIndexByte(kept, '\n')+1] // a name half written when the forwarder was killed was given to no program
	for _, name := range strings.Fields(string(kept)) {
		n.byName[name] = len(n.list)
		n.list = append(n.list, name)
	}
	if n.kept, err = os.OpenFile(file, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600); err != nil {
		return nil, err
	}
	return n, n.kept.Truncate(int64(len(kept)))
}

// address is the one name has, the next free one if it had none. It reports false when none is left.
func (n *names) address(name string) (netip.Addr, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	i, ok := n.byName[name]
	if !ok {
		if len(n.list) >= maxNames {
			return netip.Addr{}, false
		}
		if _, err := n.kept.WriteString(name + "\n"); err != nil {
			return netip.Addr{}, false
		}
		i = len(n.list)
		n.byName[name] = i
		n.list = append(n.list, name)
	}
	first := captureRange.Addr().As4()
	return netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, binary.BigEndian.Uint32(first[:])+uint32(i)+1))), true
}

// name is the one addr was given to.
func (n *names) name(addr netip.Addr) (string, bool) {
	first, a := captureRange.Addr().As4(), addr.As4()
	i := int(binary.BigEndian.Uint32(a[:])-binary.BigEndian.Uint32(first[:])) - 1
	n.mu.Lock()
	defer n.mu.Unlock()
	if i < 0 || i >= len(n.list) {
		return "", false
	}
	return n.list[i], true
}

// answer is the reply to one DNS query, or nil for what is none.
func (n *names) answer(query []byte) []byte {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil || h.Response || h.OpCode != 0 {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	h = dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true}
	var addr netip.Addr
	// Any other question gets an empty answer: a program that asks for IPv6 too then settles on IPv4.
	if q.Type == dnsmessage.TypeA && q.Class == dnsmessage.ClassINET {
		name := strings.TrimSuffix(q.Name.String(), ".")
		// DNS lets a label hold any byte: only a host name can stand in a CONNECT request.
		ok := name != "" && strings.Trim(name, hostLetters) == ""
		name = strings.ToLower(name)
		switch {
		case !ok:
		case n.own[name]:
			addr = netip.AddrFrom4([4]byte{127, 0, 0, 1})
		default:
			addr, ok = n.address(name)
		}
		if !ok {
			h.RCode = dnsmessage.RCodeServerFailure
		}
	}
	b := dnsmessage.NewBuilder(make([]byte, 0, 512), h)
	b.EnableCompression()
	b.StartQuestions()
	b.Question(q)
	if addr.IsValid() {
		b.StartAnswers()
		b.AResource(dnsmessage.ResourceHeader{Name: q.Name, Class: q.Class, TTL: nameSeconds}, dnsmessage.AResource{A: addr.As4()})
	}
	reply, err := b.Finish()
	if err != nil {
		return nil
	}
	return reply
}

// resolve answers the sandbox's DNS queries until c is closed.
func (n *names) resolve(c net.PacketConn) error {
	query := make([]byte, 1500)
	for {
		size, from, err := c.ReadFrom(query)
		if err != nil {
			return err
		}
		if reply := n.answer(query[:size]); reply != nil {
			c.WriteTo(reply, from)
		}
	}
}

// captured carries a connection that redirect sent here to the name its address was given to, or to the address itself in a granted range, and resets any other.
func (f *forwarder) captured(c *net.TCPConn) {
	if to, err := originalDst(c); err == nil {
		if name, ok := f.names.name(to.Addr()); ok {
			f.stream(c, fmt.Sprintf("%s:%d", name, to.Port()))
			return
		}
		// The forwarder holds no list of ranges: redirect sends it no other address, and the proxy rules on each.
		if !captureRange.Contains(to.Addr()) && !to.Addr().IsLoopback() {
			f.stream(c, to.String())
			return
		}
	}
	c.SetLinger(0)
	c.Close()
}

// originalDst is where a connection was going before redirect sent it to the forwarder.
func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}
	var to *unix.IPv6Mreq // the kernel answers with a sockaddr_in: this is x/sys's getsockopt of at least that size
	if cerr := raw.Control(func(fd uintptr) {
		to, err = unix.GetsockoptIPv6Mreq(int(fd), unix.IPPROTO_IP, unix.SO_ORIGINAL_DST)
	}); cerr != nil {
		return netip.AddrPort{}, cerr
	}
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("original destination: %w", err)
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(to.Multiaddr[4:8])), binary.BigEndian.Uint16(to.Multiaddr[2:4])), nil
}

// tunnel asks the proxy for target as a program that honours HTTPS_PROXY does, and reports whether it got it.
func tunnel(up io.ReadWriter, c io.Writer, target string) bool {
	if _, err := up.Write(frame("CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n\r\n")); err != nil {
		return false
	}
	var reply []byte
	for !bytes.Contains(reply, []byte("\r\n\r\n")) { // whole frames: the stream is left where join takes it up
		var length [4]byte
		if _, err := io.ReadFull(up, length[:]); err != nil {
			return false
		}
		size := int(binary.BigEndian.Uint32(length[:]))
		if size == 0 || len(reply)+size > maxFrame {
			return false
		}
		reply = append(reply, make([]byte, size)...)
		if _, err := io.ReadFull(up, reply[len(reply)-size:]); err != nil {
			return false
		}
	}
	head, rest, _ := bytes.Cut(reply, []byte("\r\n\r\n"))
	if status := bytes.Fields(head); len(status) < 2 || string(status[1]) != "200" {
		return false
	}
	_, err := c.Write(rest) // a server that speaks first may already have
	return err == nil
}
