package network

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/ethernet"
)

var (
	ErrInvalidHardwareAddr = errors.New("Error: Invalid hardware address")
	ErrInvalidIp           = errors.New("Error: Invalid IP address")
)

// func (host *Host) BuildArpPacket(op Operation) {
// var buf bytes.Buffer
// }

func (host *Host) ArpRequest(ip netip.Addr) error {
	err := host.getDetails()
	if err != nil {
		return err
	}
	arp, err := BuildArpPacket(OperationRequest, host.HardwareMac, net.HardwareAddr(host.TargetMac), host.Ip, ip)
	if err != nil {
		// handle error when creating arp requests
	}

	return nil
}

// build a new arp packet for the input operation and the addresses for both sender and target
func BuildArpPacket(op Operation, senderHW, targetHW net.HardwareAddr, senderIp, targetIp netip.Addr) (*ArpPacket, error) {
	if len(senderHW) < 6 || len(targetHW) < 6 {
		return nil, ErrInvalidHardwareAddr
	}
	if !bytes.Equal(ethernet.Broadcast, targetHW) && len(senderHW) != len(targetHW) {
		return nil, ErrInvalidHardwareAddr
	}
	var invalidIp netip.Addr
	if !senderIp.IsValid() || !senderIp.Is4() {
		return nil, ErrInvalidIp
	}
	if !targetIp.Is4() || targetIp == invalidIp {
		return nil, ErrInvalidIp
	}

	return &ArpPacket{
		HardwareType: uint16(1),
		// EtherType for ipv4
		ProtocolType:       uint16(ethernet.EtherTypeIPv4),
		HardwareAddrLength: uint8(len(senderHW)),
		IpLength:           uint8(4),
		SenderHardwareAddr: senderHW,
		SenderIp:           senderIp,
		TargetHardwareAddr: targetHW,
		TargetIp:           targetIp,
	}, nil
}
