package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// granted is an address range the pod reaches through its proxy, on one TCP port.
type granted struct {
	network netip.Prefix
	port    uint16
}

// grant reads a range and its port, as 10.20.0.0/24:5432.
func grant(s string) (granted, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return granted{}, fmt.Errorf("%q names no port", s)
	}
	r, err := netip.ParsePrefix(s[:i])
	if err != nil {
		return granted{}, err
	}
	// As the machine's own, a range over either would take the pod's connections to itself, or to the names it looked up.
	if !r.Addr().Is4() || r != r.Masked() || r.Overlaps(captureRange) || r.Overlaps(netip.MustParsePrefix("127.0.0.0/8")) {
		return granted{}, fmt.Errorf("%v is not an IPv4 network outside 127.0.0.0/8 and %v", r, captureRange)
	}
	port, err := strconv.ParseUint(s[i+1:], 10, 16)
	if err != nil || port == 0 {
		return granted{}, fmt.Errorf("%q is no TCP port", s[i+1:])
	}
	return granted{r, uint16(port)}, nil
}

// redirect sends the forwarder the sandbox's DNS queries at 127.0.0.1 and its TCP to captureRange and to each granted range's port.
func redirect(args []string) error {
	fs := flag.NewFlagSet("redirect", flag.ExitOnError)
	forwarder := fs.Uint("forwarder", 0, "the uid the pod's forwarder runs as")
	var ranges []granted
	fs.Func("range", "an IPv4 range and a TCP port, as 10.20.0.0/24:5432, that the pod reaches through its proxy by address; may repeat", func(s string) error {
		r, err := grant(s)
		if err == nil {
			ranges = append(ranges, r)
		}
		return err
	})
	fs.Parse(args)
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}
	// As an address of lo, captureRange is this machine's own, as 127.0.0.0/8 is, and glibc's AI_ADDRCONFIG sees IPv4.
	route, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return err
	}
	defer route.Close()
	attributes := netlink.NewAttributeEncoder()
	attributes.Bytes(unix.IFA_LOCAL, captureRange.Addr().AsSlice())
	local, err := attributes.Encode()
	if err != nil {
		return err
	}
	ifaddrmsg := binary.NativeEndian.AppendUint32([]byte{unix.AF_INET, byte(captureRange.Bits()), 0, unix.RT_SCOPE_HOST}, uint32(lo.Index))
	if _, err := route.Execute(netlink.Message{
		Header: netlink.Header{Type: unix.RTM_NEWADDR, Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Replace},
		Data:   append(ifaddrmsg, local...),
	}); err != nil {
		return err
	}
	// With no other device the guest has no route to a range: ip route replace local <network> dev lo src 198.18.0.0
	for _, r := range ranges {
		attributes := netlink.NewAttributeEncoder()
		attributes.Bytes(unix.RTA_DST, r.network.Addr().AsSlice())
		attributes.Uint32(unix.RTA_OIF, uint32(lo.Index))
		attributes.Bytes(unix.RTA_PREFSRC, captureRange.Addr().AsSlice())
		local, err := attributes.Encode()
		if err != nil {
			return err
		}
		rtmsg := []byte{unix.AF_INET, byte(r.network.Bits()), 0, 0, unix.RT_TABLE_LOCAL, unix.RTPROT_STATIC, unix.RT_SCOPE_HOST, unix.RTN_LOCAL, 0, 0, 0, 0}
		if _, err := route.Execute(netlink.Message{
			Header: netlink.Header{Type: unix.RTM_NEWROUTE, Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Replace},
			Data:   append(rtmsg, local...),
		}); err != nil {
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
	toForwarder := []expr.Any{
		&expr.Immediate{Register: 1, Data: binary.BigEndian.AppendUint16(nil, capturePort)},
		&expr.Redir{RegisterProtoMin: 1},
	}
	// ip daddr <network>
	to := func(network netip.Prefix) []expr.Any {
		return []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
			&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: net.CIDRMask(network.Bits(), 32), Xor: make([]byte, 4)},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network.Addr().AsSlice()},
		}
	}
	tcp := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
	}
	// ip daddr 198.18.0.0/15 meta l4proto tcp redirect to :3127
	c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: slices.Concat(to(captureRange), tcp, toForwarder)})
	for _, r := range ranges {
		// ip daddr <network> tcp dport <port> redirect to :3127
		c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: slices.Concat(to(r.network), tcp, []expr.Any{
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, r.port)},
		}, toForwarder)})
	}
	// ip daddr 127.0.0.1 udp dport 53 redirect to :3127
	c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: append([]expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{127, 0, 0, 1}},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, 53)},
	}, toForwarder...)})
	// While the forwarder is down another user's process can bind its port: what such a socket sends from there is dropped, so it answers no lookup and takes no connection.
	guard := c.AddChain(&nftables.Chain{Name: "guard", Table: table, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter})
	// ip saddr 127.0.0.1 th sport 3127 meta skuid != <forwarder> drop
	c.AddRule(&nftables.Rule{Table: table, Chain: guard, Exprs: []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 12, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{127, 0, 0, 1}},
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binary.BigEndian.AppendUint16(nil, capturePort)},
		&expr.Meta{Key: expr.MetaKeySKUID, Register: 1},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binary.NativeEndian.AppendUint32(nil, uint32(*forwarder))},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}})
	for _, r := range ranges {
		// The pod itself would answer a range's other ports: ip daddr <network> reject with icmp type admin-prohibited
		c.AddRule(&nftables.Rule{Table: table, Chain: guard, Exprs: append(to(r.network), &expr.Reject{Type: unix.NFT_REJECT_ICMP_UNREACH, Code: 13})})
	}
	return c.Flush()
}
