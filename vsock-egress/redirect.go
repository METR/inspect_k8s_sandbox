package main

import (
	"encoding/binary"
	"flag"
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
)

// redirect sends the sandbox's TCP connections to siblingRange to the forwarder: it needs NET_ADMIN, so it runs once, before any program of the task.
func redirect(args []string) error {
	flag.NewFlagSet("redirect", flag.ExitOnError).Parse(args) // it has none: -h ends here, before the namespace is changed
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	route, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return err
	}
	defer route.Close()
	attributes := netlink.NewAttributeEncoder()
	attributes.Bytes(unix.IFA_LOCAL, ownRange.Addr().AsSlice())
	local, err := attributes.Encode()
	if err != nil {
		return err
	}
	// An address of lo makes its whole range this machine's own, and glibc's AI_ADDRCONFIG then sees IPv4 in a guest with no other.
	ifaddrmsg := binary.NativeEndian.AppendUint32([]byte{unix.AF_INET, byte(ownRange.Bits()), 0, unix.RT_SCOPE_HOST}, uint32(lo.Index))
	if _, err := route.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_NEWADDR, Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Replace},
		Data:   append(ifaddrmsg, local...),
	}); err != nil {
		return err
	}

	c, err := nftables.New()
	if err != nil {
		return err
	}
	table := c.AddTable(&nftables.Table{Family: nftables.TableFamilyIPv4, Name: "vsock_egress"})
	chain := c.AddChain(&nftables.Chain{Name: "output", Table: table, Type: nftables.ChainTypeNAT,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest})
	first := siblingRange.Addr().As4()
	// ip daddr 198.18.0.0/16 meta l4proto tcp redirect to :3128
	c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: net.CIDRMask(siblingRange.Bits(), 32), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: first[:]},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Immediate{Register: 1, Data: binary.BigEndian.AppendUint16(nil, forwarderPort)},
		&expr.Redir{RegisterProtoMin: 1},
	}})
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
