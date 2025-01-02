package main

import (
	"bytes"
	"flag"
	"os"
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
	Help         bool

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

	flagSet := flag.NewFlagSet("general", flag.ContinueOnError)

	buf := bytes.NewBuffer([]byte{})
	flagSet.SetOutput(buf)

	flagSet.BoolVar(&options.Verbose, "v", true, "Verbose output (default setting)") // 'cause it's set to true I first need to check other possible output flags
	flagSet.BoolVar(&options.JSONOutput, "j", false, "Enable JSON output")
	flagSet.BoolVar(&options.EnableProgressBar, "pb", false, "Enable progress bar instead of continuos printing")
	flagSet.BoolVar(&options.HelpFlag, "h", false, "Usage: ")
	flagSet.BoolVar(&options.PruneAllDocker, "pr", true, "Prune all docker instances after running (default)")
	flagSet.BoolVar(&options.ListSimsFlag, "ls", false, "List simulation flags")

	// if err := flagSet.Parse(os.Args[1:]); err != nil {
	// 	log.Fatalln(err.Error())
	// }
	flagSet.Parse(os.Args[1:])

	return options
}

func ParseNetOptions() *NetOptions {
	options := &NetOptions{}

	flagSet := flag.NewFlagSet("net", flag.ContinueOnError)

	buf := bytes.NewBuffer([]byte{})
	flagSet.SetOutput(buf)

	flagSet.BoolVar(&options.Help, "h", false, "Usage of net: ")
	flagSet.StringVar(&options.FunFlag, "f", "scan", "Specify what function to run on network sim (default to 'scan')")
	flagSet.StringVar(&options.IfaceFlag, "i", "eno1", "Network interface to use for network sim")
	flagSet.StringVar(&options.IpFlag, "ip", "", "IP to use in network scan (either single or CIDR)")
	flagSet.StringVar(&options.PortFlag, "p", "22", "Port (or a port range using '-') to use for port scanner")

	flagSet.BoolVar(&options.ServiceDiscovery, "service", false, "Enable service discovery")
	flagSet.BoolVar(&options.Ping, "ping", true, "Enable ping functionality")
	flagSet.BoolVar(&options.ArpPing, "arp", false, "Enable ARP ping")
	flagSet.StringVar(&options.Proxy, "proxy", "", "Set proxy")
	flagSet.BoolVar(&options.OnlyHostDiscovery, "ohs", false, "Only perform host discovery")

	flagSet.IntVar(&options.timeFlag, "d", 2, "Set timeout in seconds (default to 2s)")
	options.Timeout = time.Duration(options.timeFlag)

	flagSet.Parse(os.Args[2:])

	return options
}

func ParseSimOptions() *SimOptions {
	options := SimOptions{}

	flagSet := flag.NewFlagSet("sim", flag.ContinueOnError)

	buf := bytes.NewBuffer([]byte{})
	flagSet.SetOutput(buf)

	flagSet.BoolVar(&options.CodebaseScanFlag, "cb", false, "Run security scan on provided codebase")
	flagSet.BoolVar(&options.NetFlag, "net", false, "Run security scan on a given network")
	flagSet.BoolVar(&options.DDOS, "dd", false, "Run ddos script on url or a codebase in docker")
	flagSet.BoolVar(&options.SQLi, "sq", false, "Run SQL injection simulation on url or a codebase in docker")
	flagSet.StringVar(&options.RunFlag, "run", "", "Specify what simulation test you want to run")
	flagSet.BoolVar(&options.DBTestFlag, "db", false, "Run database security scan on provided codebase")

	// if err := flagSet.Parse(os.Args[1:]); err != nil {
	// 	log.Fatalln(err.Error())
	// }

	// var args []string
	// args = append(args, os.Args[1])
	// if err := flagSet.Parse(args); err != nil {
	// 	log.Fatalln(err.Error())
	// }

	flagSet.Parse(os.Args[1:])

	return &options
}
