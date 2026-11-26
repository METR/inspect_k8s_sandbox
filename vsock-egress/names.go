package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// nameTTL is how long a client may keep an answer: short, so that one from a forwarder since restarted, which the new one does not know, is asked for again.
const nameTTL = 5

// names gives each name the sandbox looks up an address of nameRange and tells a connection to that address which name it was for: the lookup that counts is made where the connection leaves.
type names struct {
	mu     sync.Mutex
	byName map[string]netip.Addr
	byAddr map[netip.Addr]string
	next   uint32 // how many addresses have been given out
}

func newNames() *names {
	return &names{byName: map[string]netip.Addr{}, byAddr: map[netip.Addr]string{}}
}

// address is name's own, the same one each time it is asked; past the range's 32,766 the longest held goes to the next name.
func (n *names) address(name string) netip.Addr {
	n.mu.Lock()
	defer n.mu.Unlock()
	if addr, known := n.byName[name]; known {
		return addr
	}
	hosts := uint32(1)<<(32-nameRange.Bits()) - 2 // but the range's first address and its last
	first := nameRange.Addr().As4()
	addr := netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, binary.BigEndian.Uint32(first[:])+1+n.next%hosts)))
	n.next++
	if held, taken := n.byAddr[addr]; taken {
		delete(n.byName, held)
	}
	n.byName[name], n.byAddr[addr] = addr, name
	return addr
}

// named is the name addr was given for, or none.
func (n *names) named(addr netip.Addr) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.byAddr[addr]
}

// answer is the reply to a DNS question: an address of nameRange for a name's A record, and no record for any other question, an IPv6 address among them.
func (n *names) answer(question []byte) []byte {
	var parser dnsmessage.Parser
	header, err := parser.Start(question)
	if err != nil || header.Response {
		return nil
	}
	asked, err := parser.Question()
	if err != nil {
		return nil
	}
	reply := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true})
	reply.EnableCompression()
	reply.StartQuestions()
	reply.Question(asked)
	reply.StartAnswers()
	if asked.Class == dnsmessage.ClassINET && asked.Type == dnsmessage.TypeA {
		name := strings.ToLower(strings.TrimSuffix(asked.Name.String(), "."))
		reply.AResource(dnsmessage.ResourceHeader{Name: asked.Name, Class: asked.Class, TTL: nameTTL}, dnsmessage.AResource{A: n.address(name).As4()})
	}
	packed, err := reply.Finish()
	if err != nil {
		return nil
	}
	return packed
}

// converse answers the questions of a connection capture found going to the resolver, each after its length, until its client ends it or asks nothing more.
func (n *names) converse(c net.Conn) {
	defer c.Close()
	for size := make([]byte, 2); ; {
		c.SetDeadline(time.Now().Add(handshakeWait))
		if _, err := io.ReadFull(c, size); err != nil {
			return
		}
		question := make([]byte, binary.BigEndian.Uint16(size))
		if _, err := io.ReadFull(c, question); err != nil {
			return
		}
		reply := n.answer(question)
		if reply == nil {
			return
		}
		if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(reply))), reply...)); err != nil {
			return
		}
	}
}

// serve answers the questions that capture sends to l.
func (n *names) serve(l net.PacketConn) error {
	question := make([]byte, 512) // a question is one name: none is longer
	for {
		size, from, err := l.ReadFrom(question)
		if err != nil {
			return err
		}
		if reply := n.answer(question[:size]); reply != nil {
			l.WriteTo(reply, from)
		}
	}
}
