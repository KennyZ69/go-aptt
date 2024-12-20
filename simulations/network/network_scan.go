package network

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	netlibk "github.com/KennyZ69/netlibK"
)

func RawNetworkScan(ips []net.IP, ifi *net.Interface, timeout time.Duration, countFlag *int) (NetReport, error) {
	var report NetReport
	var activeHosts = make(chan net.IP, len(ips))
	var wg sync.WaitGroup

	log.Println("Setting up the client")
	c, err := netlibk.ICMPSetClient(ifi)
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	if err = c.Conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		log.Fatalf("Error setting the deadline for connection: %v\n", err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		err = rawDiscoverHosts(c, ips, activeHosts, &wg)
		if err != nil {
			log.Printf("Error discovering active hosts: %v\n", err)
		}
	}()

	wg.Wait()

	var active int
	var hostArr []net.IP
	var stats = make(chan IpStats, len(activeHosts))

	for host := range activeHosts {
		targetIp := host
		fmt.Printf("Discover active host: %v\n", targetIp.String())
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats <- MeasurePings(*countFlag, targetIp, timeout)
		}()
		hostArr = append(hostArr, host)
		active++
	}

	wg.Wait()

	log.Printf("Found %d active hosts\n", active)

	return report, nil
}

func rawDiscoverHosts(c *netlibk.Client, ips []net.IP, activeHosts chan<- net.IP, wg *sync.WaitGroup) error {
	var notActive, failed int
	payload := []byte("Hello world!")

	for _, ip := range ips {
		wg.Add(1)
		go func(targetIp net.IP) {
			defer func() {
				log.Printf("Finished pings on %s\n", targetIp.String())
				wg.Done()

			}()
			fmt.Printf("Pinging %s\n", ip.String())
			latency, active, err := c.Ping(ip, payload)
			if err != nil {
				log.Printf("Failed to ping %s: %v\n", ip.String(), err)
				failed++
			}
			if active {
				log.Printf("%s is active with latency of %v\n", ip.String(), latency)
				activeHosts <- ip
			} else {
				log.Printf("%s is not active\ncontinuing ...\n", ip.String())
				notActive++
			}
		}(ip)
	}

	go func() {
		wg.Wait() // ensure all goroutines finish
		close(activeHosts)
	}()

	var err error = nil
	if failed == len(ips) {
		err = fmt.Errorf("All pings failed, try to run with sudo ...")
	}

	return err
}

func Network_scan(ips []net.IP, ifi *net.Interface, timeout time.Duration, countFlag *int) (NetReport, error) {
	var report NetReport
	var activeHosts = make(chan net.IP, len(ips))
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		err := discoverHosts(ips, activeHosts, timeout, &wg)
		if err != nil {
			log.Printf("There was an error discovering the active hosts: %v\n", err)
		}
	}()

	wg.Wait()
	// close(activeHosts)

	if len(activeHosts) == 0 {
		return report, fmt.Errorf("No active host were discovered\n")
	}

	var activeCounter int
	var hostsArr []net.IP
	var stats = make(chan IpStats, len(activeHosts))

	for host := range activeHosts {

		fmt.Printf("Discovered active host: %s \n", host.String())
		wg.Add(1)
		go func() {
			defer wg.Done()
			stats <- MeasurePings(*countFlag, host, timeout)
		}()
		hostsArr = append(hostsArr, host)
		activeCounter++
	}

	wg.Wait()

	log.Printf("Number of active hosts: %d\n", activeCounter)

	var ipToMac map[string](chan net.HardwareAddr)
	var count int

	if len(hostsArr) > 0 {
		retMac, err := discoverMAC(hostsArr[0], ifi, timeout)
		if err != nil {
			return report, fmt.Errorf("Error getting mac addr for the first host in arr")
		}
		fmt.Printf("Got the retMac: %v\n", retMac)

		for _, host := range hostsArr {
			hostMac, err := discoverMAC(host, ifi, timeout)
			if err != nil {
				return report, fmt.Errorf("There was an error getting mac addr for %s\n", host.String())
			}

			if bytes.Equal(retMac, hostMac) {
				count++
			}

			// if I have sent arp more than thrice to the same addr then break from the loop
			if count > 3 {
				fmt.Println("Had to stop looking for mac addr")
				break
			}

			if ipToMac[host.String()] == nil {
				// ipToMac[host.String()] = make(chan net.HardwareAddr)
				ipToMac[host.String()] <- hostMac
				log.Printf("Storing %s : %v\n", host.String(), hostMac)
			} else {
				continue
			}
		}

	}

	// TODO: get the ip stats for each active host
	// TODO: for each active host found I can do the arp requests to find its mac address

	return report, nil
}

func discoverHosts(ips []net.IP, activeHosts chan<- net.IP, timeout time.Duration, wg *sync.WaitGroup) error {
	var notActiveCounter, failedCounter int
	payload := []byte("Hello world!")

	log.Println("Trying to ping the found IPs and get a list of active ones...")

	for _, ip := range ips {

		wg.Add(1)
		go func(targetIp net.IP) {
			defer func() {
				log.Printf("Finished pings on %s\n", targetIp.String())
				wg.Done()
			}()
			fmt.Printf("Pinging %s\n", targetIp.String())
			latency, active, err := netlibk.HigherLvlPing(targetIp, payload, timeout)
			if err != nil {
				log.Printf("Failed to ping %s: %v\n", targetIp.String(), err)
				failedCounter++
			}
			if active {
				log.Printf("Host %s is active with latency of %v\nAdding to the list of active hosts...\n", targetIp.String(), latency)
				activeHosts <- targetIp
			} else {
				log.Printf("%s is not active host\ncontinuing...\n", targetIp.String())
				notActiveCounter++
			}
		}(ip)

	}

	go func() {
		wg.Wait() // Ensure all goroutines finish
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

func discoverMAC(ip net.IP, ifi *net.Interface, timeout time.Duration) (net.HardwareAddr, error) {
	c, err := netlibk.ARPSetClient(ifi)
	if err != nil {
		return nil, fmt.Errorf("Error setting up client: %v\n", err)
	}
	defer c.Close()

	if err = c.Conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("Error setting deadline on client: %v\n", err)
	}

	mac, err := c.ResolveMAC(ip, true)
	fmt.Println(ip, mac)
	if err != nil || mac == nil {
		return nil, fmt.Errorf("Error resolving mac addr: %v\n", err)
	}

	return mac, nil
}
