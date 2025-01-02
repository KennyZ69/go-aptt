package network

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/KennyZ69/portslibK/scanner"
)

// now I need to make a simple ping functionality to discover hosts and print it to logger and return error
func PingScan(ipArr []net.IP, timeout time.Duration) (time.Duration, error) {
	var wg sync.WaitGroup

	log.Println("Running ping function ...")
	start := time.Now()
	activeHostChan := make(chan net.IP)

	err := discoverHosts(ipArr, activeHostChan, timeout, &wg)

	fmt.Println("List of active hosts: ")
	for h := range activeHostChan {
		// log.Printf("Found active host: %s\n", h.String())
		fmt.Println("  ", h.String())
	}
	return time.Since(start), err
}

func PortScan(portFlag string, scanType string, ipArr []net.IP, timeout time.Duration) (time.Duration, error) {
	log.Println("Running port scanner ...")
	// var wg sync.WaitGroup

	start := time.Now()

	portArr, err := parsePortFlag(portFlag)
	if err != nil {
		return time.Since(start), fmt.Errorf("Port scan failed: %v\n", err)
	}

	// wg.Add(1)
	for _, ip := range ipArr {
		// go func(targetIP net.IP) {
		// 	defer wg.Done()
		// 	fmt.Println("running on", targetIP.String())
		// 	s, err := scanner.CreateScanner(scanType, targetIP, portArr, timeout)
		// 	if err != nil {
		// 		log.Fatalln(err)
		// 	}
		//
		// 	if err = s.Start(); err != nil {
		// 		log.Fatalln(err)
		// 	}
		// 	s.Stop()
		// }(ip)

		// Right now it should be fine doing it this way for testing etc...
		// but later I might remake the library functions to give me some results that I could later print here
		// because it could be ran on a lot of ports and multiple IPs
		// and then I must utilize go routines with just simple table results printed afterwards

		// TODO: in portslibK make the udp scan to end retrying after 2 retries

		s, err := scanner.CreateScanner(scanType, ip, portArr, timeout)
		if err != nil {
			log.Fatalln(err)
		}

		if err = s.Start(); err != nil {
			log.Fatalln(err)
		}
		s.Stop()

	}

	// go wg.Wait()

	return time.Since(start), nil
}
