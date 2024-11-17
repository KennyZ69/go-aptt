package network

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

// parse the user inputs to know what I am working with
// looking for "/" (cidr notation) or hostnames/domains or then single ips or range or ips
func ParseInputs(args []string) (string, string, bool, error) {
	if len(args) == 1 {
		input := args[0]
		if strings.Contains(input, "/") {
			// this means that it would be a CIDR notation
			_, _, err := net.ParseCIDR(input)
			if err != nil {
				return "", "", false, fmt.Errorf("Invalid CIDR\n")
			}
			// return ip.String(), "", true, nil
			return input, "", true, nil
		}
		// single ip or a hostname (domain name)
		ip := resolveHostname(input)
		if ip == "" {
			return "", "", false, fmt.Errorf("Error resolving the hostname or a single ip: invalid ip or hostname\n")
		}
		return ip, ip, false, nil
	}
	if len(args) == 2 {
		addr_start := resolveHostname(args[0])
		addr_end := resolveHostname(args[1])
		if addr_start == "" || addr_end == "" {
			return "", "", false, fmt.Errorf("Error: invalid ip range from %v to %v\n", args[0], args[1])
		}
		return addr_start, addr_end, false, nil
	}

	return "", "", false, fmt.Errorf("Invalid number of arguments passed\n")
}

func resolveHostname(input string) string {
	ips, err := net.LookupIP(input)
	if err != nil || len(ips) == 0 {
		fmt.Println("Error looking up the host to resolve")
		return ""
	}
	return ips[0].String()
}

func GenerateIPs(startIP, endIP string) []string {
	var ips []string
	start := net.ParseIP(startIP)
	// start := strings.Split(startIP, ".")
	// end := strings.Split(endIP, ".")
	end := net.ParseIP(endIP)

	for ip := start; compareIPs(ip, end) <= 0; inc(ip) {
		ips = append(ips, ip.String())
	}
	log.Printf("Generating IPs to scan from %v to %v ... \n", startIP, endIP)

	return ips
}

// helper function to increment
func toInt(s string) int {
	var n, err = strconv.Atoi(s)
	if err != nil {
		fmt.Printf("Error converting ip suffix into int to icrement: %v\n", err)
	}
	return n
}

func compareIPs(startIp, endIp net.IP) int {
	for i := 0; i < len(startIp); i++ {
		if startIp[i] < endIp[i] {
			return -1
		} else if startIp[i] > endIp[i] {
			return 1
		}
	}
	return 0
}

func GenerateFromCIDR(input string) []string {
	ip, ipNet, _ := net.ParseCIDR(input)
	// there cannot be invalid cidr input now because the parsing catches it

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	log.Printf("Generating IPs to scan from %v to %v ... \n", ips[0], ips[len(ips)-1])

	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
