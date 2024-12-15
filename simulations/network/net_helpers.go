package network

import (
	"encoding/binary"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"

	netlibk "github.com/KennyZ69/netlibK"
	"github.com/google/gopacket"
	layers "github.com/google/gopacket/layers"
)

type MapResult struct {
	Ip       net.IP
	Protocol string
	Port     int
	Header   string
}

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

	SYNFlag = 0x02
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

func ulimit() int {
	out, err := exec.Command("sh", "-c", "ulimit -n").Output()
	if err != nil {
		log.Fatalf("Error getting routines limit: %v\n", err) // end point for the program
	}

	s := strings.TrimSpace(string(out))
	ulimit, err := strconv.Atoi(s)
	// if err != nil || s == "unlimited" {
	// 	// log.Fatal(err)
	// 	return 100
	// }
	if err != nil {
		log.Fatal(err)
	}

	return ulimit
}

func BuildSynPacket(srcIp, destIp net.IP, port int) ([]byte, int, error) { // return the packet with source port and error
	// make the header for the tcp connection -> src and dest ports
	tcpHeader := make([]byte, 20)
	// srcPort := uint16(49152 + rand.Intn(65535-49152)) // dynamic range of ports to use as source port
	// srcPort := uint16(rand.Intn(65535-1024) + 1024) // Random port in ephemeral range
	p := (rand.Intn(65535-1024) + 1024)
	srcPort := uint16(p)
	destPort := uint16(port)

	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	binary.BigEndian.PutUint16(tcpHeader[2:4], destPort)

	tcpHeader[12] = (5 << 4) // data offset
	tcpHeader[13] = SYNFlag

	ipHeader := make([]byte, 20)
	ipHeader[0] = 0x45 // version and header length (IHL)
	ipHeader[8] = 64   // TTL
	ipHeader[9] = 6    // Protocol
	copy(ipHeader[12:16], srcIp.To4())
	copy(ipHeader[16:20], destIp.To4())

	checksum := tcpChecksum(srcIp.To4(), destIp.To4(), tcpHeader)
	binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)

	// combine them to return
	return append(ipHeader, tcpHeader...), p, nil
}

func BuildRST(srcIp, destIp net.IP, srcPort, destPort int) ([]byte, error) {
	// build headers for the rst (reset)
	ipH := layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    destIp,
		Protocol: layers.IPProtocolTCP,
	}

	tcpH := layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(destPort),
		RST:     true,
	}

	if err := tcpH.SetNetworkLayerForChecksum(&ipH); err != nil {
		return nil, fmt.Errorf("Error setting checksum for tcp header in rst: %v\n", err)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &ipH, &tcpH); err != nil {
		return nil, fmt.Errorf("Error serializing RST packet: %v\n", err)
	}

	return buf.Bytes(), nil
}

func tcpChecksum(srcIp, destIp net.IP, tcpHeader []byte) uint16 {
	h := make([]byte, 12)
	copy(h[0:4], srcIp.To4())
	copy(h[4:8], destIp.To4())
	h[9] = 6
	binary.BigEndian.PutUint16(h[10:12], uint16(len(tcpHeader)))

	data := append(h, tcpHeader...)
	return checksum(data)
}

// I guess I could do this function as a global util in a library or something
func checksum(data []byte) uint16 {
	var sum uint32

	// converting, shifting the bits and the "|" is a bitwise OR to combine those two 8-bit values into one 16 bit val
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	// ensuring no overflown bits remain there, extracting them and adding them to the lower 16 bits
	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)

	// one's complement -> inverts all bits so 0 to 1 and 1 to 0
	return uint16(^sum)
}

func isSYNAck(p []byte) bool {
	if len(p) < 40 {
		return false
	}

	tcpHeader := p[20:40]

	flags := tcpHeader[13]
	return flags&0x12 == 0x12
}
