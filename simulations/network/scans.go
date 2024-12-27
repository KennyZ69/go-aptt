package network

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
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
