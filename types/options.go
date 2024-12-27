package types

import (
	"flag"
	"time"
)

type GeneralOptions struct {
	Verbose            bool
	CSVOutput          bool
	JSONOutput         bool
	DisableUpdateCheck bool
	EnableProgressBar  bool
}

type NetOptions struct {
	ServiceDiscovery  bool
	ArpPing           bool
	Ping              bool
	Proxy             string
	OnlyHostDiscovery bool
	Timeout           time.Duration
	timeFlag          int
}

type SimOptions struct {
	// TODO
	// add the simulation functions as bool flags here
	NetFlag bool
	DDOS    bool
}

// TODO
// finish this file
func ParseOptions() *GeneralOptions {
	options := &GeneralOptions{}

	flagSet := flag.NewFlagSet("general", flag.ExitOnError)

	flagSet.BoolVar(&options.Verbose, "verbose", false, "Enable verbose output")

	return options
}

func ParseNetOptions() *NetOptions {
	options := &NetOptions{}

	flagSet := flag.NewFlagSet("net", flag.ExitOnError)

	flagSet.BoolVar(&options.ServiceDiscovery, "service", false, "Enable service discovery")
	flagSet.BoolVar(&options.Ping, "ping", true, "Enable ping functionality")
	flagSet.BoolVar(&options.ArpPing, "arp", false, "Enable ARP ping")
	flagSet.StringVar(&options.Proxy, "proxy", "", "Set proxy")
	flagSet.BoolVar(&options.OnlyHostDiscovery, "ohs", false, "Only perform host discovery")

	flagSet.IntVar(&options.timeFlag, "timeout", 2, "Set timeout in seconds (default to 2s)")
	options.Timeout = time.Duration(options.timeFlag)

	return options
}
