package network

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	netlibk "github.com/KennyZ69/netlibK"
)

func Mapper(ipArr []net.IP, ifi *net.Interface, p string) (NetReport, error) {
	var report NetReport
	var wg sync.WaitGroup
	var ports []int
	var err error

	// var result MapResult

	if strings.Contains(p, "-") {
		ports, err = parsePortFlag(p)
		if err != nil {
			return NetReport{}, fmt.Errorf("Error: Could not convert port flag to int: %v\n", err)
		}
		// fmt.Println(ports)
	} else {
		port, err := strconv.Atoi(p)
		if err != nil {
			return NetReport{}, fmt.Errorf("Error: Could not convert port flag to int: %v\n", err)
		}
		ports = append(ports, port)
	}

	smLimit := ulimit()
	semaphore := make(chan struct{}, smLimit) // get the limit for semaphore by running ulimit on the client's device

	// but this is testing just one given port for each ip addr
	// I could later make it so that for each ip there is every port tested from a given range or a default range
	for _, ip := range ipArr {
		for _, port := range ports {

			wg.Add(1)
			go func(host net.IP, port int) {
				defer wg.Done()
				log.Println("Running usual tcp conn scan")
				err := scanTCPPort(host, port, semaphore)
				if err != nil {
					fmt.Println(err)
				}
				log.Println("Running syn requests to scan")
				if err = scanSYNPort(host, port, ifi, semaphore); err != nil {
					fmt.Println(err)
				}
			}(ip, port)
		}
	}

	wg.Wait()

	return report, nil
}

func scanTCPPort(ip net.IP, port int, semaphore chan struct{}) error {
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	c, err := net.DialTimeout("tcp", addr, time.Second*2) // hardcode 2 seconds timeout
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(time.Second * 2)
			scanTCPPort(ip, port, semaphore)
		} else {
			fmt.Println("\nTCP - Port", port, "closed on", ip.String())
			return err
		}
	}

	defer c.Close()

	fmt.Printf("\nTCP - Port %d is open on %s\n", port, ip.String())

	h, err := getPortHeader(c)
	if err != nil || h == "" {
		// return fmt.Errorf("Error getinng port header: %v\n", err)
		fmt.Printf("\nCouldn't get the header for port %d on %s: %v\n", port, ip.String(), err)
	} else {
		fmt.Printf("\nHeader for port %d on %s: %s\n", port, ip.String(), h)
	}
	return nil
}

func scanSYNPort(ip net.IP, port int, ifi *net.Interface, semaphore chan struct{}) error {
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	c, err := net.ListenPacket("ip4:tcp", ip.String())
	if err != nil {
		return err
	}
	defer c.Close()

	cl, err := netlibk.New(ifi, c)
	if err != nil {
		return fmt.Errorf("Error making new client for port scanning: %v\n", err)
	}

	// build packet
	p, srcP, err := BuildSynPacket(cl.SourceIp, ip, port)
	if err != nil {
		return err
	}

	// send the packet
	n, err := c.WriteTo(p, &net.IPAddr{IP: ip})
	if err != nil {
		return fmt.Errorf("Error writing the packet to connection: %v\n", err)
	}

	// listen for a response
	buf := make([]byte, 4096)
	c.SetReadDeadline(time.Now().Add(time.Second * 2))
	n, _, err = c.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("No response from syn request: %v\n", err)
	}

	// now analyze somehow the gotten response

	if isSYNAck(buf[:n]) {
		fmt.Printf("\nSYN - Port %d is open on %s\n", port, ip.String())
		rstPacket, err := BuildRST(cl.SourceIp, ip, srcP, port)
		if err != nil {
			fmt.Printf("Error building RST packet: %v\n", err)
		}
		_, err = c.WriteTo(rstPacket, &net.IPAddr{IP: ip})
		if err != nil {
			fmt.Printf("Error sending RST packet: %v\n", err)
		}
	} else {
		fmt.Printf("\nSYN - Port %d on %s is closed or filtered\n", port, ip.String())
		fmt.Println("This SYN scan results may vary from a full 3-way TCP handshake")
	}

	return nil
}

func getPortHeader(c net.Conn) (string, error) {
	buf := make([]byte, 2048)
	c.SetReadDeadline(time.Now().Add(time.Second * 3))

	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("Error reading to buffer")
	}

	h := strings.TrimSpace(string(buf[:n]))

	return h, nil
}

func getProtocol(c net.Conn, ip net.IP, port int) (string, error) {
	if port == 80 || port == 8080 {
		fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s \r\n\r\n", ip.String())
	}

	return "", nil
}

func parsePortFlag(p string) ([]int, error) {
	var ports []int

	parts := strings.Split(p, "-")
	if len(parts) > 2 { // i can have two parts of a range or a single port number
		return nil, fmt.Errorf("Invalid port range given\n")
	}

	ps, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil, err
	}

	pe, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}

	for i := ps; i <= pe; i++ {
		ports = append(ports, i)
	}

	return ports, nil

}
