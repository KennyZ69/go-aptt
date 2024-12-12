package network

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

func Mapper(ipArr []net.IP, ifi *net.Interface, port int) (NetReport, error) {
	var report NetReport
	var wg sync.WaitGroup
	smLimit := ulimit()
	semaphore := make(chan struct{}, smLimit) // get the limit for semaphore by running ulimit on the client's device

	// but this is testing just one given port for each ip addr
	// I could later make it so that for each ip there is every port tested from a given range or a default range
	for _, ip := range ipArr {

		wg.Add(1)
		go func(host net.IP) {
			defer wg.Done()
			err := scanTCPPort(host, port, semaphore)
			if err != nil {
				fmt.Print(err)
			}
			// the function itself prints if the port is open on given ip addr
		}(ip)
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
			// return fmt.Errorf("Error dialing tcp: %v\n", err)
			fmt.Println(port, "closed")
		}
	}

	c.Close()

	fmt.Printf("Port %d is open on %s\n", port, ip.String())
	return nil
}
