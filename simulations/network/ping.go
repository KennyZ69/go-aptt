package network

import "time"

type ICMP struct {
	Type     uint8 // Type 8 = echo req
	Code     uint8 // 0 for echo
	Checksum uint16
	Id       uint16
	SeqNum   uint16 // sequence number
}

// implementing ICMP ping function myself, returs whether given host is active and the latency
func ping(addr string, timeout time.Duration) (bool, time.Duration)

func getChecksum(data []byte) uint16 {
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
