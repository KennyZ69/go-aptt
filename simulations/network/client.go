package network

import (
	"net"
	"net/netip"
)

type Client struct {
	netInf     *net.Interface
	ip         netip.Addr
	packetConn net.PacketConn
}

const ARP_PROTOCOL = 0x0806
