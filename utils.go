package main

import (
	"log"
	"net"

	netlibk "github.com/KennyZ69/netlibK"
)

func GetInputIPs(ifaceFlag, ipStart, ipEnd *string) ([]net.IP, *net.Interface) {
	var addrs []string
	var ipArr []net.IP
	ifi, err := net.InterfaceByName(*ifaceFlag)
	if err != nil {
		log.Fatalf("Error getting the net interface: %v\n", err)
	}

	addrs = append(addrs, *ipStart, *ipEnd)

	addr_start, addr_end, isCidr, err := netlibk.ParseIPInputs(addrs)
	if err != nil {
		log.Fatalf("Error parsing the input values: %v\n", err)
	}

	if isCidr {
		ipArr = netlibk.GenerateIPsFromCIDR(addr_start)
	} else {
		ipArr = netlibk.GenerateIPs(addr_start, addr_end)
	}

	log.Println("Found the ips: ", ipArr)

	return ipArr, ifi
}
