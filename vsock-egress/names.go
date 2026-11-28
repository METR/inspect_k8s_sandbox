package main

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// nameTTL is how long a client may keep an answer: short, so that one a forwarder started again no longer knows is asked for again.
const nameTTL = 5 * time.Second

// names gives each name the sandbox looks up an address of nameRange and tells a connection to that address which name it was for.
type names struct {
	mu     sync.Mutex
	byName map[string]*alias
	byAddr map[netip.Addr]string
	next   uint32    // addresses given out since the pod started, by this forwarder and any before it
	since  time.Time // when this forwarder started
	kept   string    // the file that holds next: a forwarder started again gives no address an earlier one gave another name
	now    func() time.Time
}

// alias is a name's address, and when the name was last looked up or connected to.
type alias struct {
	addr  netip.Addr
	asked time.Time
}

func newNames(kept string) *names {
	n := &names{byName: map[string]*alias{}, byAddr: map[netip.Addr]string{}, since: time.Now(), kept: kept, now: time.Now}
	if was, err := os.ReadFile(kept); err == nil && len(was) == 4 {
		n.next = binary.BigEndian.Uint32(was)
	}
	return n
}

// address is name's own, the same one each time it is asked. With every address given there is none until one's last answer has twice outlived its time to live.
func (n *names) address(name string) (addr netip.Addr, room bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	if held, known := n.byName[name]; known {
		held.asked = now
		return held.addr, true
	}
	hosts := uint32(1)<<(32-nameRange.Bits()) - 2 // but the range's first address and its last
	if uint32(len(n.byAddr)) < hosts {
		// With every address given and room in this table, the next was an earlier forwarder's, whose answer with it may still be in use.
		if n.next >= hosts && now.Sub(n.since) < 2*nameTTL {
			return netip.Addr{}, false
		}
		first := nameRange.Addr().As4()
		addr = netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, binary.BigEndian.Uint32(first[:])+1+n.next%hosts)))
		if n.kept != "" {
			// Whole or not at all: a count cut short would start the addresses over, as would one not kept.
			if os.WriteFile(n.kept+".new", binary.BigEndian.AppendUint32(nil, n.next+1), 0o600) != nil || os.Rename(n.kept+".new", n.kept) != nil {
				return netip.Addr{}, false
			}
		}
		n.next++ // only once it is kept: an address passed over would leave the table room when the count comes round to one in use
	} else {
		var oldest string
		for held, at := range n.byName {
			if oldest == "" || at.asked.Before(n.byName[oldest].asked) {
				oldest = held
			}
		}
		if now.Sub(n.byName[oldest].asked) < 2*nameTTL {
			return netip.Addr{}, false
		}
		addr = n.byName[oldest].addr
		delete(n.byName, oldest)
	}
	n.byName[name], n.byAddr[addr] = &alias{addr, now}, name
	return addr, true
}

// named is the name addr was given for, or none: a connection to it counts as the name asked for again, so a name in use keeps its address.
func (n *names) named(addr netip.Addr) string {
	n.mu.Lock()
	defer n.mu.Unlock()
	name := n.byAddr[addr]
	if held := n.byName[name]; held != nil {
		held.asked = n.now()
	}
	return name
}

// carried says whether a proxy would take name: it has a dot, and nothing that could end the line that asks for it.
func carried(name string) bool {
	return strings.Contains(name, ".") && strings.Trim(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.") == ""
}

// answer is the reply to a DNS question: an address of nameRange for the A record of a name a proxy would take, and no record for any other.
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
	said := dnsmessage.Header{ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true}
	var addr netip.Addr
	if name := strings.TrimSuffix(asked.Name.String(), "."); asked.Class == dnsmessage.ClassINET && asked.Type == dnsmessage.TypeA && carried(name) {
		var room bool
		if addr, room = n.address(strings.ToLower(name)); !room { // lowered once it is all ASCII: as text, a Kelvin sign is a k
			said.RCode = dnsmessage.RCodeServerFailure
		}
	}
	reply := dnsmessage.NewBuilder(nil, said)
	reply.EnableCompression()
	reply.StartQuestions()
	reply.Question(asked)
	reply.StartAnswers()
	if addr.IsValid() {
		reply.AResource(dnsmessage.ResourceHeader{Name: asked.Name, Class: asked.Class, TTL: uint32(nameTTL / time.Second)}, dnsmessage.AResource{A: addr.As4()})
	}
	packed, err := reply.Finish()
	if err != nil {
		return nil
	}
	return packed
}

// converse answers the questions on a connection capture found going to the resolver, each after its length.
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
func (n *names) serve(l net.PacketConn) {
	question := make([]byte, 512) // a question is one name: none is longer
	for {
		size, from, err := l.ReadFrom(question)
		if err != nil {
			return
		}
		if reply := n.answer(question[:size]); reply != nil {
			l.WriteTo(reply, from)
		}
	}
}
