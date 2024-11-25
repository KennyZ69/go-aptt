package network

import (
	"net"
	"net/netip"
)

// func (host *Host) BuildArpPacket(op Operation) {
// var buf bytes.Buffer
// }

func (host *Host) ArpRequest(ip netip.Addr) error {
	arp, err := BuildArpPacket(OperationRequest, host.HardwareMac, net.HardwareAddr(host.TargetMac), host.Ip, ip)
	if err != nil {
		// handle error when creating arp requests
	}

	return nil
}

// build a new arp packet for the input operation and the addresses for both sender and target
func BuildArpPacket(op Operation, senderHW, targetHW net.HardwareAddr, senderIp, targetIp netip.Addr) (*ArpPacket, error)
