package main

import (
	"database/sql"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KennyZ69/go-aptt/simulations/dbs"
	_ "github.com/lib/pq"
)

func securityScan(target string, db *sql.DB) (string, error) {
	fmt.Printf("Running security scans on: %v\n", target)

	// rootDir := "."
	goFiles, err := getGoFiles(target)
	if err != nil {
		return "Error getting the go files running the Security Scan: report: ", fmt.Errorf(err.Error())
	}
	fmt.Println("Found the go files: ", goFiles)

	var parsedGoFiles []*ast.File

	for _, goFile := range goFiles {
		parsedFile, err := parseGoFiles(goFile)
		if err != nil {
			fmt.Printf("Error parsing %s file in the main func: %v\n", goFile, err)
		}

		log.Printf("Checking %s for hardcoded secrets\n", goFile)
		vuln := simulations.CheckForSecrets(parsedFile, goFile)
		fmt.Println("Found hardcoded secrets: ", vuln)

		log.Printf("Checking %s for SQL Dynamic Queries in the codebase\n", goFile)
		sqlVuln := simulations.CheckForDynamicSqlQueries(parsedFile, goFile)
		fmt.Println("Found SQL Dynamic Query vulnerabilities: ", sqlVuln)

		parsedGoFiles = append(parsedGoFiles, parsedFile)
		fmt.Printf("Parsing %s file and appending into parsed files array\n", goFile)
	}

	// Possible ast printing of the files for debugging
	// ast.Print(token.NewFileSet(), parsedGoFiles)

	// Now check for vulnerabilities, possible exploitaitons, and make report messages with suggestions on fixes
	sqlInjectionResults := simulations.SimulateSQLInjection(db)
	fmt.Println("Reports of the sql injection simulations:")
	for _, result := range sqlInjectionResults {
		log.Println(result)
	}

	return "Security Scan ended now! Watch back for your reports.", nil
}

var (
	helpCommand  = flag.Bool("help", false, "Usage: ")
	codebaseTest = flag.Bool("codebase", false, "Run Security Scan on provided codebase (given file or directory)")
	networkTest  = flag.Bool("network", false, "Run Security Scan on network with given address")
	dbTest       = flag.Bool("db", false, "Run Security Scan on database with given host, user, port and type")
)

func main() {

	var modeCommand string
	flag.StringVar(&modeCommand, "test_mode", "safe", "specify the mode in what you want to run the test: safe / attack")

	// Pass target (the root directory or the directory from which the person wants to do the checks) as a command-line argument for now
	// Maybe later make it optional to what will be ran in the tests, e.g. somebody doesnt want to test database things so he chooses the option without testing against db
	// Mkae it like: go-aptt --type --action --optional_other_things

	flag.Parse()

	args := flag.Args()
	fmt.Println(args)

	// Test whether there is a flag and argument with that
	if len(os.Args) < 2 {
		fmt.Println("Missing arguments: see: go-aptt --help")
		os.Exit(1)
	}

	// target := os.Args[1]

	if *helpCommand {
		fmt.Print(`
	--network [adress] : Scan the network on given adress in sandbox, attacking it
	--db	   [type]   : Scan the database given you also add things like db-host, user, port etc..
	--codebase [target]: Scan the codebase from a given directory (or file)
	--[command] --safe : Run the security scans in safe mode so without attacking against provided base
	--[command] --attack : Run the security scans in attack mode so it uses malicious code against provided base in a sandbox

`)
		os.Exit(0)
	}

	if *codebaseTest {
		targetBase := os.Args[1]
		os.Exit(0)
	}

	if *dbTest {
		vulns, err := dbs.DB_Scan()
		if err != nil {

		}
		os.Exit(0)
	}

	if *networkTest {
		// run the network test
	}

	report, err := securityScan(target, db)
	if err != nil {
		fmt.Printf("Found vulnerabilities: report: %v\n", report)
		os.Exit(1)
	} else {
		fmt.Println("Security scan passed with no vulnerabilities and no errors")
		os.Exit(0)
	}
}

func getGoFiles(root string) ([]string, error) {
	var goFiles []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (filepath.Ext(d.Name()) == ".go") && !strings.Contains(d.Name(), "_test.go") && !strings.Contains(d.Name(), "_simulation.go") {
			goFiles = append(goFiles, path)
		}
		return nil
	})
	return goFiles, err
}

func parseGoFiles(filePath string) (*ast.File, error) {
	fset := token.NewFileSet()
	// parse the go file
	node, err := parser.ParseFile(fset, filePath, nil, parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("Error parsing the %s file: %v\n", filePath, err)
	}

	if node == nil {
		return nil, fmt.Errorf("Parsed file got nil nodes: %s; report: %v\n", filePath, err)
	}
	// Print the AST (for debugging purposes)
	fmt.Printf("Parsed AST for %s:\n", filePath)

	// Possible ast printing of the files for debugging
	// ast.Print(fset, node)
	return node, err
}

// Helper function to check if the file is a test file
func isTestFile(fileName string) bool {
	return filepath.Ext(fileName) == ".go" && filepath.Base(fileName)[:len(fileName)-3] == "_test"
}
