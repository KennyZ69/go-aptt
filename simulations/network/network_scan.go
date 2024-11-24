package network

import (
	"fmt"
	"log"
	"sync"
	"time"
)

func Network_scan(ips []string) (NetReport, error) {
	var report NetReport
	var activeHosts = make(chan string, len(ips))
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := discoverHosts(ips, activeHosts, time.Second*2, &wg)
		if err != nil {
			log.Printf("There was an error discovering the active hosts: %v\n", err)
		}
	}()

	wg.Wait()
	// close(activeHosts)

	var activeCounter int
	var hostsArr []string
	var stats = make(chan IpStats, len(activeHosts))

	for host := range activeHosts {
		fmt.Printf("Discovered active host: %v\n", host)
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats <- MeasurePings(host, 5)
		}()
		hostsArr = append(hostsArr, host)
		activeCounter++
	}
	// TODO: for each active host found I can do the arp requests to find its mac address

	wg.Wait()

	log.Printf("Number of active hosts: %d\n", activeCounter)

	return report, nil
}

// need to do this concurrently
func discoverHosts(ips []string, activeHosts chan<- string, timeout time.Duration, wg *sync.WaitGroup) error {
	var notActiveCounter, failedCounter int

	// defer wg.Done()

	log.Println("Trying to ping the found IPs and get a list of active ones...")

	for _, ip := range ips {

		wg.Add(1)
		go func(ip string) {
			defer func() {
				log.Printf("Finished pings on %s\n", ip)
				wg.Done()
			}()
			fmt.Printf("Pinging %s\n", ip)
			active, latency, err := Ping(ip, timeout)
			if err != nil {
				log.Printf("Failed to ping %s: %v\n", ip, err)
				// fmt.Println("You may need to run this with sudo")
				failedCounter++
			}
			if active {
				log.Printf("Host %s is active with latency of %v\nAdding to the list of active hosts...\n", ip, latency)
				activeHosts <- ip
			} else {
				log.Printf("%s is not active host\ncontinuing...\n", ip)
				notActiveCounter++
			}
		}(ip)

	}

	go func() {
		wg.Wait() // Ensure all goroutines finish
		fmt.Println("Closing channel for getting active hosts")
		// Close channel after all pings are done
		close(activeHosts)
	}()

	var err error = nil
	if failedCounter == len(ips) {
		err = fmt.Errorf("All tries for pings failed, you may need to run this with sudo or there is another problem... check your reports logs")
	}

	fmt.Println("If some host you expected to be active seems to not be, you may need to run this tool with sudo")

	return err
}
