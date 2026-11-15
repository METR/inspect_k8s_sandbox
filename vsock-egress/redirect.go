package main

import (
	"encoding/binary"
	"flag"
	"net"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// redirect sends the sandbox's DNS queries at 127.0.0.1 and its TCP connections to captureRange to the forwarder.
func redirect(args []string) error {
	fs := flag.NewFlagSet("redirect", flag.ExitOnError)
	forwarder := fs.Uint("forwarder", 0, "the uid the pod's forwarder runs as")
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
	first := captureRange.Addr().As4()
	// ip daddr 198.18.0.0/15 meta l4proto tcp redirect to :3127
	c.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: append([]expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: 16, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: net.CIDRMask(captureRange.Bits(), 32), Xor: make([]byte, 4)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: first[:]},
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
	}, toForwarder...)})
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
	return c.Flush()
}
