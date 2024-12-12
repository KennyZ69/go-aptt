package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/KennyZ69/go-aptt/simulations/dbs"
	"github.com/KennyZ69/go-aptt/simulations/ddos"
	"github.com/KennyZ69/go-aptt/simulations/inter"
	"github.com/KennyZ69/go-aptt/simulations/network"
	"github.com/KennyZ69/go-aptt/simulations/sqli"
	"github.com/KennyZ69/go-aptt/types"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

// The flags to use to specify which part of the tool the client is going to use whether it be network scanner or codebase scanner or what...
var (
	pruneAllCmd  = flag.Bool("prune", false, "Add to prune all docker images and volumes after running your tests")
	helpCommand  = flag.Bool("h", false, "Usage: ")
	simsCommand  = flag.Bool("sims", false, "Specific simulation tests: ")
	codebaseTest = flag.Bool("codebase", false, "Run Security Scan on provided codebase (given file or directory)")
	networkTest  = flag.Bool("network", false, "Run Security Scan on network with given address")
	dbTest       = flag.Bool("db", false, "Run Security Scan on database with given host, user, port and type")
	runCommand   = flag.Bool("run", false, "Specify what exact simulation test you want to run")
)

// flags for specific scan / parts of the tool e.g. the network scanner
var (
	funFlag = flag.String("f", "", "Specifiy the function to be ran by goapt")

	// set a network interface for arp traffic (eth0 or ...have to find out)
	ifaceFlag = flag.String("i", "eth0", "Network interface to use for ARP traffic")

	// get ip for the scan, either a range or single ip
	ipStart = flag.String("ips", "", "Set the starting ip address")
	ipEnd   = flag.String("ipe", "", "Set the ending ip address")

	// timeout flag
	timeoutFlag = flag.Duration("d", 2*time.Second, "timeout to send the arp requests")

	// count of e.g. requests
	countFlag = flag.Int("c", 5, "specify the count of requests sent")

	// set the mode of a simulation
	simMode = flag.String("m", "safe", "Mode to run simulation in: -m <safe / attack>")

	// port number to scan for open ports
	portFlag = flag.Int("p", 22, "Port to scan on ip addr")
)

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("There was an error loading the .env file: ", err)
	}
	torControlPassword := os.Getenv("TOR_CONTROL_PASSWORD")

	// Pass target (the root directory or the directory from which the person wants to do the checks) as a command-line argument for now
	// Maybe later make it optional to what will be ran in the tests, e.g. somebody doesnt want to test database things so he chooses the option without testing against db
	// Mkae it like: go-aptt --type --action --optional_other_things

	flag.Parse()

	args := flag.Args()

	// Test whether there is a flag and argument with that
	if len(os.Args) < 2 {
		fmt.Println("Missing arguments and flags: see: go-aptt --help")
		os.Exit(-1)
	}

	if !*codebaseTest && !*dbTest && !*networkTest && !*helpCommand && !*simsCommand && !*runCommand {
		fmt.Println("Error: None or bad flags provided. You must provide one flag: --codebase --database --network")
		os.Exit(-1)
	}

	if (*codebaseTest && *dbTest) || (*codebaseTest && *networkTest) || (*dbTest && *networkTest) {
		fmt.Println("Error: Multiple flags provided. Use just one flag at a time")
		os.Exit(-1)
	}

	if *networkTest && *helpCommand {
		fmt.Print(`
	Usage of the network feature:
		-h : help command for network
		-f : function to be ran
		-is : single ip or start of ip range
		-ie : end of ip range

`)
		os.Exit(0)
	}

	if *helpCommand {
		fmt.Print(`
	--network   [IP] : Scan the network on given adress in sandbox, based on provided mode (default = safe)
	--network [range start IP] [range end IP]: Run a network and port scan on the given range of IP addresses
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
	First run the command --run followed by the type of test simulation you want to run:

	If you want to run the DoS test you have two options ->	
	-> --run dos [language] [target app] [number of requests] [concurrency of requests (e.g. 50)] [port of your app] : 
		Run the DoS simulation in an isolated docker enviroment against a copy of your provided app
	-> --run dos [target url] [num of reqs] [concurrency] [possibly endpoint]:
		Run the DoS simulation against your running app if you dont worry about it crashing for 
			**DISCLAIMER** : Do not run this on your production app if you are not sure whether it would do any harm
	-> --run sqli [targer url]:
	-> --run sqli [language] [target codebase] [* port]: (ran in sandbox)
		Run the SQL Injection simulation against your app (finding the possible inputs), providing feedback
			**DISCLAIMER** : Do not run this on your production app if you are not sure whether it would do any harm
`)
		os.Exit(0)
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
		vulns, err := dbs.DB_Scan(*simMode, db_type)
		if err != nil {
			log.Fatalln("There was an error while processing the DB Scan: ", err)
			os.Exit(1)
		}
		vulns_report = append(vulns_report, vulns...)
		fmt.Println("Printing the vulnerabilites found (or not) for testing purposes")
		log.Println(vulns)
	}

	if *networkTest {
		var net_report network.NetReport
		var err error
		log.Println("Setting up the network tests")

		fun := *funFlag

		ipArr, ifi := GetInputIPs(ifaceFlag, ipStart, ipEnd)

		switch fun {
		case "rscan":
			log.Println("Running raw network scan...")

			net_report, err = network.RawNetworkScan(ipArr, ifi, *timeoutFlag, countFlag)
			if err != nil {
				fmt.Printf("Error in the network scan: %v\n", err)
			}
			break

		case "scan":
			log.Println("Running higher level network scan...")

			net_report, err = network.Network_scan(ipArr, ifi, *timeoutFlag, countFlag)
			if err != nil {
				fmt.Printf("Error in the network scan: %v\n", err)
			}
			break

		case "map":
		case "mapper":
			log.Println("Running network mapper ... ")

			_, err := network.Mapper(ipArr, ifi, *portFlag)
			if err != nil {
				fmt.Printf("Error in network mapper: %v\n", err)
			}
			break

		default:
			log.Fatalf("Specify the function: -f <function>")
			os.Exit(-1)
		}

		fmt.Println(net_report)
		os.Exit(0)
	}

	if *runCommand {
		if len(args) == 0 {
			fmt.Println("Error: No specified simulation test to be ran, please use an exact test function name")
			os.Exit(1)
		} else if len(args) < 2 {
			fmt.Println("You need to specify some arguments for these types of simulations: to see more details run: --sims")
			os.Exit(1)
		}

		fun := args[0]
		switch fun {
		case "dos":
			if strings.Contains(args[1], "http") {
				url := args[1]
				numReq, _ := strconv.Atoi(args[2])
				concurrency, _ := strconv.Atoi(args[3])
				ddos.DosAttack(url, numReq, concurrency, torControlPassword)
				os.Exit(0)
			} else {
				log.Println("Cleaning the docker system from possible previous failed runs...")
				cleanupDocker()
				lang := args[1]
				target := args[2]
				numReq, _ := strconv.Atoi(args[3])
				concurrency, _ := strconv.Atoi(args[4])
				var port string
				if len(args) == 6 {
					port = args[5]
				} else {
					port = "8002"
				}
				url, err := RunDocker(lang, target, port)
				if err != nil {
					log.Fatalf("Error running the docker container function: %v\n", err)
					os.Exit(1)
				}
				conc := strconv.Itoa(concurrency)
				nReq := strconv.Itoa(numReq)
				err = exec.Command("./go-aptt", "--run", "dos", url, nReq, conc).Run()
				if err != nil {
					cleanupDocker()
					// cleanupDocker(*pruneAllCmd)
					log.Fatalf("Error running './go-aptt --run dos %s %s %s' after building the docker enviroment: %v\n", url, nReq, conc, err)
					os.Exit(1)
				}
				// ddos.DosAttack(url, numReq, concurrency)
				log.Print(`

	DoS test on your app in docker enviroment went successfully, you can look at your report in dos_sim_report.log
`)
				// exec.Command("cat", "dos_sim_report.log").Run()
				cleanupDocker()
				// cleanupDocker(*pruneAllCmd)
				os.Exit(0)
				return
			}

		case "sqli":
			arg1 := args[1]
			switch strings.HasPrefix(arg1, "http") {
			case true:
				url := arg1
				log.Println("Starting the sqli sim on ", url)
				err := sqli.SqlIn(url)
				if err != nil {
					log.Fatalf("Error in running the sql injection simulatin on %s: %v\n", url, err)
					os.Exit(1)
				}
				log.Printf("Finished testing the sqli sim on: %s\n", url)
				os.Exit(0)

			case false:
				log.Println("Cleaning the docker system from possible previous failed runs...")
				// maybe clean up the used docker container before running the sim so it ensures it wont fail the first and the person would not have to rerun it
				cleanupDocker()
				log.Println("Starting simulating sql injection in a docker enviroment")
				lang := arg1
				target := args[2]
				var port string
				if len(args) == 4 {
					port = args[3]
				} else {
					port = "8002"
				}
				url, err := RunDocker(lang, target, port)
				if err != nil {
					log.Fatalf("Error running the docker container function: %v\n", err)
					os.Exit(1)
				}

				err = waitForContainerReady(url, 8, 2*time.Second)
				if err != nil {
					log.Fatalf("Error initializing the docker container, cannot ping it: %s: %v\n", url, err)
					cleanupDocker()
					os.Exit(1)
				}

				// err = exec.Command("./go-aptt", "--run", "sqli", url).Run()
				cmd := exec.Command("./go-aptt", "--run", "sqli", url)
				cmdOutput, err := cmd.CombinedOutput()
				if err != nil {
					cleanupDocker()
					log.Fatalf("Error running './go-aptt --run sqli %s': %v\nOutput: %s\n", url, err, string(cmdOutput))
					os.Exit(1)
				}
				// if err != nil {
				// 	cleanupDocker()
				// 	// cleanupDocker(*pruneAllCmd)
				// 	log.Fatalf("Error running './go-aptt --run sqli %s ' after building the docker enviroment: %v\n", url, err)
				// 	os.Exit(1)
				// }
				log.Print(`

	Sql injection simulation on your provided codebase has finished, you can look at your report in the 'reports' directory that was made.
`)
				cleanupDocker()
				// cleanupDocker(*pruneAllCmd)
				os.Exit(0)
			}
		}
	}

	// I want to make this scan.log just for vulnerabilities from static tests, so every simulation will exit in their own condition
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

// function to run the selected docker container for the user to use as a sandbox enviroment on the port 8002
func RunDocker(language, target, port string) (string, error) {
	dockerfile := selectDockerFile(language, target, port)
	// url := fmt.Sprintf("http://localhost:%s", port)
	url := "http://localhost:8080"
	if dockerfile == "" {
		return url, fmt.Errorf("There was a problem selecting a dockerfile, please inspect that you provided a viable language or so\n")
	}

	log.Println("Starting to build the Docker image for the enviroment from " + dockerfile)
	cmd := exec.Command("docker", "build", "-f", dockerfile, "-t", "user-app", target)
	err := cmd.Run()
	if err != nil {
		log.Println("There was an error when running the docker processes")
		cleanupDocker()
		// cleanupDocker(*pruneAllCmd)
		return url, fmt.Errorf("Error building the docker image: %v\n", err)
	}
	log.Printf("Starting the Docker container on port 8080:%s\n", port)
	err = exec.Command("docker", "run", "-d", "-p", fmt.Sprintf("8080:%s", port), "--name", "user-app-container", "user-app").Run()
	if err != nil {
		log.Println("There was an error when running the docker processes")
		cleanupDocker()
		// cleanupDocker(*pruneAllCmd)
		return url, fmt.Errorf("Error running the docker image: %v\n", err)
	}

	log.Println("The docker image has been built successfully and is up and running")

	return url, nil
}

func selectDockerFile(language, target, port string) string {
	switch language {
	case "node":
	case "javascript":
	case "js":
	case "typescript":
	case "ts":
		return "dockerfiles/Dockerfile-node"
	case "go":
		if _, err := os.Stat("dockerfiles"); os.IsNotExist(err) {
			err = os.Mkdir("dockerfiles", 0755)
			if err != nil {
				log.Fatalf("Error creating the dockerfiles directory: %v\n", err)
			}
			fmt.Println("Created the dockerfiles dir")
		}

		target = strings.TrimSuffix(target, "/")
		if _, err := os.Stat("dockerfiles/Dockerfile-go"); os.IsNotExist(err) {
			version, err := getGoVersion(target + "/go.mod")
			fmt.Println("Got the go version from go.mod file")
			if err != nil {
				fmt.Println("Error in getting the go version: " + err.Error())
				return ""
			}
			if version == "" {
				fmt.Println("Go version not found, but without error, defaulting to go version 1.23.")
				version = "1.23"
			}
			data := fmt.Sprintf(`
# Base image with Go installed
FROM golang:%s-alpine

# Set the working directory inside the container
WORKDIR /app

COPY go.mod go.sum

RUN go mod download

# Copy the application source code into the container
COPY . %s

# Build the Go app
RUN go build -o userapp 

# Expose port 8080 (or the port the user app listens to)
EXPOSE %s

# Command to run the application
CMD ["./userapp"]
			`, version, target, port)

			err = os.WriteFile("dockerfiles/Dockerfile-go", []byte(data), 0644)
			if err != nil {
				log.Fatalf("Error writing into dockerfiles/Dockerfile-go: %v\n", err)
			}
			fmt.Println("Wrote the dockerfile needed")
		}
		return "dockerfiles/Dockerfile-go"
	case "python":
		return "dockerfiles/Dockerfile-python"
	default:
		log.Fatalf(`
	Unsupported language: %s
	Provide one of these: 'node', 'go', 'python'
`, language)
	}
	return ""
}

func cleanupDocker() {
	// func cleanupDocker(pruneAll bool) {
	fmt.Print(`
	========= Cleaning the docker containers and images =========
`)
	exec.Command("docker", "stop", "user-app-container").Run()
	err := exec.Command("docker", "rm", "-f", "user-app-container").Run()
	if err != nil {
		log.Printf("Error remove Docker container: user-app-container: %v\n", err)
	} else {
		log.Printf("Docker container removed successfully.")
	}
	err = exec.Command("docker", "rmi", "user-app").Run()
	if err != nil {
		log.Printf("Error removing Docker image: user-app: %v\n", err)
	} else {
		log.Println("Docker image removed successfully.")
	}
	// Optional: Prune unused images and volumes
	// if pruneAll {
	// 	err = exec.Command("docker", "system", "prune", "-f").Run()
	// 	if err != nil {
	// 		log.Printf("Failed to prune Docker system: %v\n", err)
	// 	} else {
	// 		log.Println("Unused Docker images, containers, and volumes pruned successfully.")
	// 	}
	// }
	exec.Command("docker", "builder", "prune", "-f").Run() // -f to force confirmation
}

func getGoVersion(target string) (string, error) {
	file, err := os.Open(target)
	if err != nil {
		return "", fmt.Errorf("Error: getting the go version from go.mod file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		// to find the version i can look for line starting with "go"
		line := scanner.Text()

		if strings.HasPrefix(line, "go") {
			return strings.TrimSpace(strings.TrimPrefix(line, "go")), nil
		}
	}
	if err = scanner.Err(); err != nil {
		return "", fmt.Errorf("Error: could not read the go.mod file correctly: %v", err)
	}
	return "", fmt.Errorf("No go version was found\n")
}

func waitForContainerReady(url string, maxRetries int, delay time.Duration) error {
	for i := 0; i < maxRetries; i++ {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == http.StatusOK {
			resp.Body.Close()
			return nil // Endpoint is ready
		}
		time.Sleep(delay)
	}
	return fmt.Errorf("container not ready at %s after %d attempts", url, maxRetries)
}
