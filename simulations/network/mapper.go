package network

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func Mapper(ipArr []net.IP, ifi *net.Interface, p string) (NetReport, error) {
	var report NetReport
	var wg sync.WaitGroup

	ports, err := parsePortFlag(p)
	if err != nil {
		return NetReport{}, fmt.Errorf("Error: Could not convert port flag to int: %v\n", err)
	}
	fmt.Println(ports)
	smLimit := ulimit()
	semaphore := make(chan struct{}, smLimit) // get the limit for semaphore by running ulimit on the client's device

	// but this is testing just one given port for each ip addr
	// I could later make it so that for each ip there is every port tested from a given range or a default range
	for _, ip := range ipArr {
		for _, port := range ports {

			wg.Add(1)
			go func(host net.IP, port int) {
				defer wg.Done()
				err := scanTCPPort(host, port, semaphore)
				if err != nil {
					fmt.Print(err)
				}
				// the function itself prints if the port is open on given ip addr
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
			fmt.Println("\nport", port, "closed on", ip.String())
			return err
		}
	}

	defer c.Close()

	fmt.Printf("\nPort %d is open on %s\n", port, ip.String())

	h, err := getPortHeader(c)
	if err != nil || h == "" {
		// return fmt.Errorf("Error getinng port header: %v\n", err)
		fmt.Printf("\nCouldn't get the header for port %d on %s: %v\n", port, ip.String(), err)
	} else {
		fmt.Printf("\nHeader for port %d on %s: %s\n", port, ip.String(), h)
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
	if len(parts) != 2 {
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
