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
	HelpFlag           bool
	ListSimsFlag       bool
	PruneAllDocker     bool
}

type NetOptions struct {
	FunFlag      string
	IfaceFlag    string
	IpFlag       string
	PortFlag     string
	PortScanType string

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
	CodebaseScanFlag bool
	NetFlag          bool
	DDOS             bool
	SQLi             bool // sql injection simulation
	RunFlag          string
	DBTestFlag       bool
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

	flagSet.StringVar(&options.FunFlag, "f", "scan", "Specify what function to run on network sim (default to 'scan')")
	flagSet.StringVar(&options.IfaceFlag, "i", "eth0", "Network interface to use for network sim")
	flagSet.StringVar(&options.IpFlag, "ip", "", "IP to use in network scan (either single or CIDR)")
	flagSet.StringVar(&options.PortFlag, "p", "22", "Port (or a port range using '-') to use for port scanner")

	flagSet.BoolVar(&options.ServiceDiscovery, "service", false, "Enable service discovery")
	flagSet.BoolVar(&options.Ping, "ping", true, "Enable ping functionality")
	flagSet.BoolVar(&options.ArpPing, "arp", false, "Enable ARP ping")
	flagSet.StringVar(&options.Proxy, "proxy", "", "Set proxy")
	flagSet.BoolVar(&options.OnlyHostDiscovery, "ohs", false, "Only perform host discovery")

	flagSet.IntVar(&options.timeFlag, "timeout", 2, "Set timeout in seconds (default to 2s)")
	options.Timeout = time.Duration(options.timeFlag)

	return options
}

func ParseSimOptions() *SimOptions {
	options := &SimOptions{}

	flagSet := flag.NewFlagSet("sim", flag.ExitOnError)

	flagSet.BoolVar(&options.CodebaseScanFlag, "cb", false, "Run security scan on provided codebase")
	flagSet.BoolVar(&options.NetFlag, "net", false, "Run security scan on a given network")
	flagSet.BoolVar(&options.CodebaseScanFlag, "cb", false, "Run security scan on provided codebase")
	flagSet.BoolVar(&options.DDOS, "dd", false, "Run ddos script on url or a codebase in docker")
	flagSet.BoolVar(&options.SQLi, "sq", false, "Run SQL injection simulation on url or a codebase in docker")
	flagSet.StringVar(&options.RunFlag, "run", "", "Specify what simulation test you want to run")

	return options
}
