package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

var (
	// ownRange is set aside for benchmarks (RFC 2544), so nothing a sandbox is meant to reach is in it: redirect makes it the sandbox's own, as 127.0.0.0/8 is.
	ownRange = netip.MustParsePrefix("198.18.0.0/15")
	// siblingRange is the half whose addresses stand for the sandbox's sibling services.
	siblingRange = netip.MustParsePrefix("198.18.0.0/16")
	// deliverTo is in the other half: a server on every address hears a sibling there, and one on 127.0.0.1 alone does not, as on a pod with a network card.
	deliverTo = netip.MustParseAddr("198.19.0.1")
	// nameRange is the part of the other half whose addresses stand for the names a captured sandbox looks up.
	nameRange = netip.MustParsePrefix("198.19.128.0/17")
	// resolver is where the chart's resolv.conf sends a sandbox's lookups: the DNS sidecar's place in a pod with a network card.
	resolver = netip.MustParseAddrPort("127.0.0.1:53")
)

// redirect sends the sandbox's TCP connections to siblingRange to the forwarder, and refuses what else it sends there: it needs NET_ADMIN, so it runs once, before any program of the task.
func redirect(args []string) error { return divert(args, false) }

// redirectAll does that, and sends the forwarder every other connection the sandbox makes and each name it looks up, for a sandbox that may reach the whole internet through its proxy.
func redirectAll(args []string) error { return divert(args, true) }

func divert(args []string, all bool) error {
	if len(args) > 0 { // one given for help, say, as root on a node, would make ownRange that machine's own
		return fmt.Errorf("it takes no argument, and was given %q", args)
	}
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	route, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return err
	}
	defer route.Close()
	put := func(kind netlink.HeaderType, data []byte, attributes *netlink.AttributeEncoder) error {
		encoded, err := attributes.Encode()
		if err != nil {
			return err
		}
		_, err = route.Execute(netlink.Message{
			Header: netlink.Header{Type: kind, Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Replace},
			Data:   append(data, encoded...),
		})
		return err
	}
	local := netlink.NewAttributeEncoder()
	local.Bytes(unix.IFA_LOCAL, ownRange.Addr().AsSlice())
	// An address of lo makes its whole range this machine's own, and glibc's AI_ADDRCONFIG then sees IPv4 in a guest with no other.
	if err := put(unix.RTM_NEWADDR, binary.NativeEndian.AppendUint32([]byte{unix.AF_INET, byte(ownRange.Bits()), 0, unix.RT_SCOPE_HOST}, uint32(lo.Index)), local); err != nil {
		return err
	}
	if all {
		// With no route a connection to an address of the internet ends before any rule sees it: this one leads it to the rules below, from an address no rule keeps a lookup's answer from.
		out := netlink.NewAttributeEncoder()
		out.Uint32(unix.RTA_OIF, uint32(lo.Index))
		out.Bytes(unix.RTA_PREFSRC, deliverTo.AsSlice())
		if err := put(unix.RTM_NEWROUTE, []byte{unix.AF_INET, 0, 0, 0, unix.RT_TABLE_MAIN, unix.RTPROT_STATIC, unix.RT_SCOPE_LINK, unix.RTN_UNICAST, 0, 0, 0, 0}, out); err != nil {
			return err
		}
	}

	c, err := nftables.New()
	if err != nil {
		return err
	}
	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "vsock_egress"})
	chain := c.AddChain(&nftables.Chain{Name: "output", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest})
	sent := c.AddChain(&nftables.Chain{Name: "sent", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter})
	// ip daddr [!=] range
	to := func(is expr.CmpOp, r netip.Prefix) []expr.Any {
		first := r.Addr().As4()
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: net.CIDRMask(r.Bits(), 32), Xor: make([]byte, 4)},
			&expr.Cmp{Op: is, Register: 1, Data: first[:]},
		}
	}
	// meta l4proto [!=] protocol
	over := func(is expr.CmpOp, protocol byte) []expr.Any {
		return []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: is, Register: 1, Data: []byte{protocol}}}
	}
	rule := func(in *nftables.Chain, then expr.Any, matches ...[]expr.Any) {
		exprs := []expr.Any{}
		for _, match := range matches {
			exprs = append(exprs, match...)
		}
		if then == nil { // redirect to :3128
			exprs = append(exprs, &expr.Immediate{Register: 1, Data: binary.BigEndian.AppendUint16(nil, forwarderPort)}, &expr.Redir{RegisterProtoMin: 1})
		} else {
			exprs = append(exprs, then)
		}
		c.AddRule(&nftables.Rule{Table: table, Chain: in, Exprs: exprs})
	}
	drop := &expr.Verdict{Kind: expr.VerdictDrop}
	rule(chain, nil, to(expr.CmpOpEq, siblingRange), over(expr.CmpOpEq, unix.IPPROTO_TCP))
	// The range is the sandbox's own, so its own server would take a datagram meant for a sibling, and its own kernel answer a ping.
	rule(sent, drop, to(expr.CmpOpEq, siblingRange), over(expr.CmpOpNeq, unix.IPPROTO_TCP))
	if all {
		elsewhere := [][]expr.Any{to(expr.CmpOpNeq, netip.MustParsePrefix("127.0.0.0/8")), to(expr.CmpOpNeq, ownRange)}
		// th dport 53
		lookup := []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, resolver.Port())},
		}
		// A lookup: to the resolver either way, and one sent out of the sandbox as a datagram, which nothing would carry there.
		rule(chain, nil, to(expr.CmpOpEq, netip.PrefixFrom(resolver.Addr(), 32)), over(expr.CmpOpEq, unix.IPPROTO_UDP), lookup)
		rule(chain, nil, to(expr.CmpOpEq, netip.PrefixFrom(resolver.Addr(), 32)), over(expr.CmpOpEq, unix.IPPROTO_TCP), lookup)
		rule(chain, nil, append(elsewhere, over(expr.CmpOpEq, unix.IPPROTO_UDP), lookup)...)
		// A connection to a name, at the address the forwarder gave it, or to an address that is not the sandbox's own.
		rule(chain, nil, to(expr.CmpOpEq, nameRange), over(expr.CmpOpEq, unix.IPPROTO_TCP))
		rule(chain, nil, append(elsewhere, over(expr.CmpOpEq, unix.IPPROTO_TCP))...)
		// Nothing carries what is not TCP: it fails where it is sent, as to a sibling.
		rule(sent, drop, to(expr.CmpOpEq, nameRange), over(expr.CmpOpNeq, unix.IPPROTO_TCP))
		rule(sent, drop, append(elsewhere, over(expr.CmpOpNeq, unix.IPPROTO_TCP))...)
	}
	return c.Flush()
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
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(to.Multiaddr[4:8])), binary.BigEndian.Uint16(to.Multiaddr[2:4])), nil
}
