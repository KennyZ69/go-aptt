package network

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	netlibk "github.com/KennyZ69/netlibK"
)

type IpStats struct {
	Ip         net.IP
	Mac        net.HardwareAddr
	Latency    time.Duration
	PacketLoss float64
	Error      error
}

type NetReport struct {
	IP      net.IP           // or maybe netIp
	MacAddr net.HardwareAddr // or later some other type
	Report  string
	Stats   IpStats
}

type Host struct {
	TargetIp    net.IP
	TargetMac   net.HardwareAddr
	HardwareMac net.HardwareAddr
	Ip          net.IP
}

type ArpPacket struct {
	HardwareType       uint16    // 2 bytes
	ProtocolType       uint16    // 2 bytes
	HardwareAddrLength uint8     // 1 byte
	IpLength           uint8     // 1 byte
	Operation          Operation // 2 bytes
	SenderHardwareAddr net.HardwareAddr
	SenderIp           netip.Addr
	TargetHardwareAddr net.HardwareAddr
	TargetIp           netip.Addr
}

// just to specify the operation as either reply or request
type Operation uint16

const (
	OperationRequest Operation = 1
	OperationReply   Operation = 2

	// listing out all the possible port numbers to scan / map
	FTPdata    = 20
	FTPcontrol = 21
	SSH        = 22
	Telnet     = 23
	DNS        = 53
	HTTP       = 80
	HTTPS      = 443
	MySQL      = 3306
	PostgreSQL = 5432
	RDP        = 3389 // remote desktop protocol
)

func (nr *NetReport) WriteReport() {}

// Discover the sender ip and sender mac address and set them to the host
func (host *Host) getDetails() error {
	iface, err := getCurrentNetwork()
	if err != nil {
		return err
	}

	host.Ip, err = getIpAddr(iface)
	if err != nil {
		return err
	}

	host.HardwareMac = iface.HardwareAddr
	return nil
}

func getCurrentNetwork() (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("Error getting network interfaces: %v\n", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 && iface.HardwareAddr != nil {
			return &iface, nil
		}
	}
	return nil, fmt.Errorf("Could not find the current network interface\n")
}

// func getIpAddr(iface *net.Interface) (net.IP, error) {
func getIpAddr(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		// return nil, fmt.Errorf("Error getting the ip address from found net interface: %v\n", err)
		return nil, fmt.Errorf("Error getting the ip address from found net interface: %v\n", err)
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if ok && !ipNet.IP.IsLoopback() {
			// if ipNet.IP.To4() != nil {
			// return ipNet.IP, nil
			// }
			ipAddr := net.IP(ipNet.IP.To4())
			if ok {
				return ipAddr, nil
			}
		}
	}

	// return nil, fmt.Errorf("Could not find corresponding ip address\n")
	return nil, fmt.Errorf("Could not find corresponding ip address\n")
}

func MeasurePings(count int, targetIp net.IP, timeout time.Duration) IpStats {
	var totalLatency, minLatency, maxLatency time.Duration
	var sent, received int

	for i := 0; i < count; i++ {
		latency, replied, err := netlibk.HigherLvlPing(targetIp, []byte("Measuring ..."), timeout)
		sent++
		if err != nil {
			log.Printf("Error when measuring ip stats on %s: %v\n", targetIp.String(), err)
			return IpStats{
				Ip:      targetIp,
				Error:   err,
				Latency: latency,
			}
		}

		if replied {
			received++
			totalLatency += latency
			if minLatency == 0 || latency < minLatency {
				minLatency = latency
			}
			if latency > maxLatency {
				maxLatency = latency
			}
		}
	}

	packetLoss := float64(sent-received) / float64(sent) * 100
	fmt.Printf("%s:\nPackets sent: %d; Received: %d; Lost: %d (%.2f%% loss)\n", targetIp, sent, received, sent-received, packetLoss)

	if received > 0 {
		fmt.Printf("Latency (ms):\nMin: %v; Max: %v; Avg: %v\n", minLatency, maxLatency, (totalLatency / time.Duration(received)))
	}

	return IpStats{
		Ip:         targetIp,
		Error:      nil,
		Latency:    totalLatency / time.Duration(received),
		PacketLoss: packetLoss,
	}
}
