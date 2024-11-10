package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/KennyZ69/go-aptt/simulations/dbs"
	"github.com/KennyZ69/go-aptt/simulations/ddos"
	"github.com/KennyZ69/go-aptt/simulations/inter"
	"github.com/KennyZ69/go-aptt/simulations/sqli"
	"github.com/KennyZ69/go-aptt/types"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var (
	pruneAllCmd  = flag.Bool("prune-all", false, "Add to prune all docker images and volumes after running your tests")
	helpCommand  = flag.Bool("help", false, "Usage: ")
	simsCommand  = flag.Bool("sims", false, "Specific simulation tests: ")
	codebaseTest = flag.Bool("codebase", false, "Run Security Scan on provided codebase (given file or directory)")
	networkTest  = flag.Bool("network", false, "Run Security Scan on network with given address")
	dbTest       = flag.Bool("db", false, "Run Security Scan on database with given host, user, port and type")
	runCommand   = flag.Bool("run", false, "Specify what exact simulation test you want to run")
)

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("There was an error loading the .env file: ", err)
	}
	torControlPassword := os.Getenv("TOR_CONTROL_PASSWORD")

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

	if !*codebaseTest && !*dbTest && !*networkTest && !*helpCommand && !*simsCommand && !*runCommand {
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
	First run the command --run followed by the type of test simulation you want to run:

	If you want to run the DoS test you have two options ->	
	-> --run dos [language] [target app] [number of requests] [concurrency of requests (e.g. 50)] [port of your app] : 
		Run the DoS simulation in an isolated docker enviroment against a copy of your provided app
	-> --run dos [target url] [num of reqs] [concurrency] [possibly endpoint]:
		Run the DoS simulation against your running app if you dont worry about it crashing for 
			**DISCLAIMER** : Do not run this on your production app if you are not sure whether it would do any harm
	-> --run sqli [targer url]:
	-> --run sqli [target codebase]: (ran in sandbox)
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
		log.Println("Starting the network tests")
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
				lang := args[1]
				target := args[2]
				numReq, _ := strconv.Atoi(args[3])
				concurrency, _ := strconv.Atoi(args[4])
				var port string
				if len(args) == 6 {
					port = args[5]
				} else {
					port = "8080"
				}
				dockerfile := selectDockerFile(lang, target, port)
				if dockerfile == "" {
					os.Exit(1)
				}
				log.Println("Starting to build the Docker image for the enviroment from " + dockerfile)
				cmd := exec.Command("docker", "build", "-f", dockerfile, "-t", "user-app", target)
				err := cmd.Run()
				if err != nil {
					log.Println("There was an error when running the docker processes")
					cleanupDocker()
					// cleanupDocker(*pruneAllCmd)
					log.Fatalf("Error building Docker image: %v\n", err)
				}
				log.Printf("Starting the Docker container on port 8080:%s\n", port)
				// somehow I should probably get the port on which the users app runs
				err = exec.Command("docker", "run", "-d", "-p", fmt.Sprintf("8080:%s", port), "--name", "user-app-container", "user-app").Run()
				if err != nil {
					log.Println("There was an error when running the docker processes")
					cleanupDocker()
					// cleanupDocker(*pruneAllCmd)
					log.Fatalf("Error running the Docker image: %v\n", err)
				}
				url := "http://localhost:8080"
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
			// switch strings.Contains(arg1, "http") {
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
				// codebase := arg1
				log.Println("Starting simulating sql injection in a docker enviroment")
				os.Exit(0)
			}

			// here I should now try to somehow discover the possible input endpoints for the running app on provided url
			// TODO: could remake this into switch with cases, yeah that would be better for sure

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
