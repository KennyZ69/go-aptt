package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/KennyZ69/go-aptt/simulations/dbs"
	"github.com/KennyZ69/go-aptt/simulations/ddos"
	"github.com/KennyZ69/go-aptt/simulations/inter"
	"github.com/KennyZ69/go-aptt/types"
	_ "github.com/lib/pq"
)

var (
	helpCommand  = flag.Bool("help", false, "Usage: ")
	simsCommand  = flag.Bool("sims", false, "Specific simulation tests: ")
	codebaseTest = flag.Bool("codebase", false, "Run Security Scan on provided codebase (given file or directory)")
	networkTest  = flag.Bool("network", false, "Run Security Scan on network with given address")
	dbTest       = flag.Bool("db", false, "Run Security Scan on database with given host, user, port and type")
	runCommand   = flag.Bool("run", false, "Specify what exact simulation test you want to run")
)

func main() {

	var modeCommand string
	flag.StringVar(&modeCommand, "test_mode", "safe", "specify the mode in what you want to run the test: safe / attack")

	// Pass target (the root directory or the directory from which the person wants to do the checks) as a command-line argument for now
	// Maybe later make it optional to what will be ran in the tests, e.g. somebody doesnt want to test database things so he chooses the option without testing against db
	// Mkae it like: go-aptt --type --action --optional_other_things

	flag.Parse()

	args := flag.Args()
	// fmt.Println(args)

	// Test whether there is a flag and argument with that
	if len(os.Args) < 2 {
		fmt.Println("Missing arguments and flags: see: go-aptt --help")
		os.Exit(-1)
	}

	if !*codebaseTest && !*dbTest && !*networkTest && !*helpCommand && !*simsCommand {
		fmt.Println("Error: None or bad flags provided. You must provide one flag: --codebase --database --network")
		os.Exit(-1)
	}

	if (*codebaseTest && *dbTest) || (*codebaseTest && *networkTest) || (*dbTest && *networkTest) {
		fmt.Println("Error: Multiple flags provided. Use just one flag at a time")
		os.Exit(-1)
	}

	// target := args[0]

	if *helpCommand {
		fmt.Print(`
	--network   [adress] : Scan the network on given adress in sandbox, based on provided mode (default = safe)
	--db	    [type]   : Scan the database given you also add things like db-host, user, port etc..
	--codebase  [target] : Scan the codebase from a given directory (or file)
	--[command] --safe   : Run the security scans in safe mode so without attacking against provided base
	--[command] --attack : Run the security scans in attack mode so it uses malicious code against provided base in a sandbox enviroment

	These are the thorough simulations / tests, if You want to run something more specific run --sims
	
	If you have a .env file and are running tests in attack mode you should provided it using --env [path to your .env file]
`)
		os.Exit(0)
	}

	if *simsCommand {
		fmt.Print(`
	--dos [target app] [target url] : Run the DoS simulation in an isolated docker enviroment against a copy of your provided app (codebase) 
			`)
	}

	var vulns_report []types.Vulnerability

	if *codebaseTest {
		if len(args) == 0 {
			fmt.Println("Error: No target provided. Please specify the target (e.g., directory, database URL, network range).")
			os.Exit(1)
		}
		targetBase := args[0]
		// fmt.Println(targetBase)
		vulns, err := inter.Codebase_scan(targetBase)
		if err != nil {
			os.Exit(1)
		}
		vulns_report = append(vulns_report, vulns...)
		fmt.Println("Printing the vulnerabilites found (or not) for testing purposes")
		log.Println(vulns)
	}

	if *dbTest {
		db_type := os.Args[1]
		fmt.Println(db_type)
		vulns, err := dbs.DB_Scan(modeCommand, db_type)
		if err != nil {
			log.Fatalln("There was an error while processing the DB Scan: ", err)
			os.Exit(1)
		}
		vulns_report = append(vulns_report, vulns...)
		fmt.Println("Printing the vulnerabilites found (or not) for testing purposes")
		log.Println(vulns)
	}

	if *networkTest {
		if len(args) == 0 {
			fmt.Println("Error: No target provided. Please specify the target (e.g., directory, database URL, network range).")
			os.Exit(1)
		}
		// run the network test
	}

	if *runCommand {
		if len(args) == 0 {
			fmt.Println("Error: No specified simulation test to be ran, please use an exact test function name")
			os.Exit(1)
		}

		fun := args[1]
		switch fun {
		case "dos":
			url := args[2]
			numReq, _ := strconv.Atoi(args[3])
			concurrency, _ := strconv.Atoi(args[4])
			ddos.DosAttack(url, numReq, concurrency)
		}
	}

	fmt.Println("Creating scan.log file")
	f, err := os.Create("scan.log")
	if err != nil {
		log.Fatalf("Error creating the scan.log file for saving the report of the scan: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	fmt.Println("Writing into scan.log")
	for _, vuln := range vulns_report {
		_, err := fmt.Fprintln(f, vuln)
		if err != nil {
			log.Fatalf("Error writing to scan.log: %v\n", err)
			os.Exit(1)
		}
	}

	os.Exit(0)
}
