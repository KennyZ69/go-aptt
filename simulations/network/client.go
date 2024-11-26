package network

import (
	"encoding/binary"
	"net"
	"net/netip"
)

type Client struct {
	netInf     *net.Interface
	ip         netip.Addr
	packetConn net.PacketConn
}

const ARP_PROTOCOL = 0x0806

// Allocate a byte slice from the data of an ARP Packet
func (p *ArpPacket) Marshal() ([]byte, error) {

	// 2 bytes for both ProtocolType and HardwareType
	// 1 byte for both of their lengths
	// and then the corresponding lengths times two 'cause they are the same
	bin := make([]byte, 2+2+1+1+p.IpLength*2+p.HardwareAddrLength*2)

	binary.BigEndian.PutUint16(bin[0:2], p.HardwareType)
	binary.BigEndian.PutUint16(bin[2:4], p.ProtocolType)

	bin[4] = p.HardwareAddrLength
	bin[5] = p.IpLength

	binary.BigEndian.PutUint16(bin[6:8], uint16(p.Operation))

	nb := 8
	hLen := int(p.HardwareAddrLength)
	ipLen := int(p.IpLength)

	copy()

}