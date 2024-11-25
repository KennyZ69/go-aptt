package network

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"time"
)

type ICMP struct {
	Type     uint8 // Type 8 = echo req
	Code     uint8 // 0 for echo
	Checksum uint16
	Id       uint16
	SeqNum   uint16 // sequence number
}

// implementing ICMP ping function myself, returs whether given host is active and the latency
func (addr *Host) Ping(timeout time.Duration) (bool, time.Duration, error) {
	// create raw icmp socket
	conn, err := net.Dial("ip4:icmp", addr.TargetIp)
	if err != nil {
		// log.Printf("Error connecting to %s for ping: %v\n", addr, err)
		return false, 0, fmt.Errorf("Error connecting to %s for ping: %v\n", addr.TargetIp, err)
	}
	defer conn.Close()

	icmpPacket := ICMP{
		Type: 8,
		Code: 0,
		// checksum will be calculated later
		// Checksum: 0,
		Id: uint16(os.Getpid() & 0xffff),
		// Id:     0x1234,
		SeqNum: 1,
	}

	packet := new(bytes.Buffer)
	// dont know whether it does matter what endian I use now or not, so will need to look into that more
	binary.Write(packet, binary.BigEndian, icmpPacket)
	payload := []byte("Incoming ping...")
	packet.Write(payload)
	// icmpPacket.Checksum = getChecksum(packet.Bytes())
	// set the checksum of the packet
	icmpPacket.checksum(packet.Bytes())

	// actually I guess I don't know why this should be resetted
	// maybe because I need to write it with the checksum also ??
	packet.Reset()

	binary.Write(packet, binary.BigEndian, icmpPacket)
	packet.Write(payload)

	// send the icmp
	start := time.Now()
	_, err = conn.Write(packet.Bytes())
	if err != nil {
		return false, 0, fmt.Errorf("Error sending icmp packet: %v\n", err)
	}

	// handle the reply
	reply := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(reply)
	if err != nil {
		return false, 0, fmt.Errorf("Error handling the icmp reply: %v\n", err)
	}

	duration := time.Since(start)

	if n < 28 { // 20 + 8 as the minimum length for ipv4 header + icmp header
		return false, 0, fmt.Errorf("Error invalid ICMP reply lenght")
	}

	replyId := binary.BigEndian.Uint16(reply[24:26])
	replySeq := binary.BigEndian.Uint16(reply[26:28])
	if replyId != icmpPacket.Id || replySeq != icmpPacket.SeqNum {
		return false, 0, fmt.Errorf("Error mismatched ICMP reply ID or Seq number")
	}

	return true, duration, nil
}

func (icmp *ICMP) checksum(data []byte) {
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
	icmp.Checksum = uint16(^sum)
	// return uint16(^sum)
}

func (host *Host) MeasurePings(count int) IpStats {
	var totalLatency, minLatency, maxLatency time.Duration
	var sent, received int

	for i := 0; i < count; i++ {
		// replied, latency, err := Ping(host, time.Second*2)
		replied, latency, err := host.Ping(time.Second * 2)
		sent++
		if err != nil {
			log.Printf("Error occured when measuring the stats: %s: %v\n", host, err)
			return IpStats{
				Ip:    host.TargetIp,
				Error: err,
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
	fmt.Printf("Ping results for %s:\n", host.TargetIp)
	fmt.Printf("    Packets Sent: %d, Received: %d, Lost: %d (%.2f%% loss)\n",
		sent, received, sent-received, packetLoss)

	if received > 0 {
		fmt.Printf("    Latency (ms): Min = %v, Max = %v, Avg = %v\n",
			minLatency,
			maxLatency,
			(totalLatency / time.Duration(received)),
		)
	}
	return IpStats{
		Ip:         host.TargetIp,
		Error:      nil,
		Latency:    totalLatency / time.Duration(received),
		PacketLoss: packetLoss,
	}
}
