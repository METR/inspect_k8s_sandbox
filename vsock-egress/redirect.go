package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"

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
	// arriveFrom is where the forwarder dials deliverTo from: at its own address a server would take a sibling for a program of its own machine (Apache's Require local).
	arriveFrom = netip.MustParseAddr("198.19.0.2")
	// nameRange is the part of the other half whose addresses stand for the names a captured sandbox looks up.
	nameRange = netip.MustParsePrefix("198.19.128.0/17")
	// resolver is where the chart's resolv.conf sends a sandbox's lookups: the DNS sidecar's place in a pod with a network card.
	resolver = netip.MustParseAddrPort("127.0.0.1:53")
)

// redirect sends the sandbox's TCP connections to siblingRange to the forwarder, and refuses what else it sends there: it needs NET_ADMIN, so it runs once, before any program of the task.
func redirect(args []string) error { return divert(args, false) }

// redirectAll, the command capture, does that, and sends the forwarder every other connection the sandbox makes and each name it looks up.
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
	local.Bytes(unix.IFA_LOCAL, deliverTo.AsSlice()) // no address of siblingRange: what the sandbox sent its own would be redirected, or dropped
	// An address of lo makes its whole range this machine's own, and glibc's AI_ADDRCONFIG then sees IPv4 in a guest with no other.
	if err := put(unix.RTM_NEWADDR, binary.NativeEndian.AppendUint32([]byte{unix.AF_INET, byte(ownRange.Bits()), 0, unix.RT_SCOPE_HOST}, uint32(lo.Index)), local); err != nil {
		return err
	}
	if all {
		// With no route a connection to the internet ends before any rule sees it. Its source is an address no rule keeps a lookup's answer from.
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
	// One ahead of iptables' nat chain, which the guest has: at one priority, which of the two runs first is not defined.
	chain := c.AddChain(&nftables.Chain{Name: "output", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATDest - 1)})
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
	rule := func(in *nftables.Chain, then []expr.Any, matches ...[]expr.Any) {
		c.AddRule(&nftables.Rule{Table: table, Chain: in, Exprs: slices.Concat(append(matches, then)...)})
	}
	// redirect to :3128
	forwarded := []expr.Any{&expr.Immediate{Register: 1, Data: binary.BigEndian.AppendUint16(nil, forwarderPort)}, &expr.Redir{RegisterProtoMin: 1}}
	drop := []expr.Any{&expr.Verdict{Kind: expr.VerdictDrop}}
	rule(chain, forwarded, to(expr.CmpOpEq, siblingRange), over(expr.CmpOpEq, unix.IPPROTO_TCP))
	// The range is the sandbox's own, so its own server would take a datagram meant for a sibling, and its own kernel answer a ping.
	rule(sent, drop, to(expr.CmpOpEq, siblingRange), over(expr.CmpOpNeq, unix.IPPROTO_TCP))
	if all {
		elsewhere := [][]expr.Any{to(expr.CmpOpNeq, netip.MustParsePrefix("127.0.0.0/8")), to(expr.CmpOpNeq, ownRange)}
		// th dport 53
		lookup := []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, resolver.Port())},
		}
		// A lookup: to the resolver either way, and one sent as a datagram to a resolver outside the sandbox, at its address or a name's, which nothing would carry there.
		rule(chain, forwarded, to(expr.CmpOpEq, netip.PrefixFrom(resolver.Addr(), 32)), over(expr.CmpOpEq, unix.IPPROTO_UDP), lookup)
		rule(chain, forwarded, to(expr.CmpOpEq, netip.PrefixFrom(resolver.Addr(), 32)), over(expr.CmpOpEq, unix.IPPROTO_TCP), lookup)
		rule(chain, forwarded, append(elsewhere, over(expr.CmpOpEq, unix.IPPROTO_UDP), lookup)...)
		rule(chain, forwarded, to(expr.CmpOpEq, nameRange), over(expr.CmpOpEq, unix.IPPROTO_UDP), lookup)
		// A connection to a name, at the address the forwarder gave it, or to an address that is not the sandbox's own.
		rule(chain, forwarded, to(expr.CmpOpEq, nameRange), over(expr.CmpOpEq, unix.IPPROTO_TCP))
		rule(chain, forwarded, append(elsewhere, over(expr.CmpOpEq, unix.IPPROTO_TCP))...)
		// Nothing carries what is not TCP: it fails where it is sent, as to a sibling.
		rule(sent, drop, to(expr.CmpOpEq, nameRange), over(expr.CmpOpNeq, unix.IPPROTO_TCP))
		rule(sent, drop, append(elsewhere, over(expr.CmpOpNeq, unix.IPPROTO_TCP))...)
	}
	if err := c.Flush(); err != nil || !all {
		return err
	}
	return proven()
}

// proven fails unless the forwarder answers a lookup sent out of the sandbox: rules the kernel took and does not follow would leave every connection hanging.
func proven() error {
	ctx, cancel := context.WithTimeout(context.Background(), dialWait)
	defer cancel()
	asks := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", "192.0.2.53:53")
	}}
	if _, err := asks.LookupIP(ctx, "ip4", "capture.invalid."); err != nil {
		return fmt.Errorf("a lookup sent out of the sandbox got no address from the forwarder: %w", err)
	}
	return nil
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
