package network

import (
	"fmt"
	"net"
	"sync"
	"time"
)

func Mapper(ipArr []net.IP, ifi *net.Interface, port int) (NetReport, error) {
	var report NetReport
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 50) // limit to 50 requests concurrently

	wg.Add(1)
	go func() {
		for _, ip := range ipArr {
			err := scanTCPPort(ip, port, &wg, semaphore)
			if err != nil {
				fmt.Print(err)
			}
			// the function itself prints if the port is open on given ip addr
		}
	}()

	return report, nil
}

func scanTCPPort(ip net.IP, port int, wg *sync.WaitGroup, semaphore chan struct{}) error {
	defer wg.Done()
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	addr := fmt.Sprintf("%s:%d", ip.String(), port)
	c, err := net.DialTimeout("tcp", addr, time.Second*2)
	if err != nil {
		return fmt.Errorf("Error dialing tcp: %v\n", err)
	}
	defer c.Close()

	fmt.Printf("Port %d is open on %s\n", port, ip.String())
	return nil
}
