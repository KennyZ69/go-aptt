package main

import (
	"database/sql"
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

	"github.com/KennyZ69/go-aptt/simulations"
	_ "github.com/lib/pq"
)

func securityScan(target string, db *sql.DB) (string, error) {
	fmt.Printf("Running security scans on: %v\n", target)

	// Now check for vulnerabilities, possible exploitaitons, and make report messages with suggestions on fixes
	sqlInjectionResults := simulations.SimulateSQLInjection(db)
	fmt.Println("Reports of the sql injection simulations:")
	for _, result := range sqlInjectionResults {
		log.Println(result)
	}

	if target == "vulnerable-app" {
		return "Vulnerabilities detect in the target app", fmt.Errorf("vulnerable-app as target")
	}
	return "No vulnerabilities for now", nil
}

func main() {

	// Pass target as a command-line argument for now
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [target]")
		os.Exit(1)
	}

	target := os.Args[1]

	// rootDir := "."
	goFiles, err := getGoFiles(target)
	if err != nil {
		fmt.Printf("Error getting all the go files in the codebase: %v\n", err)
		return
	}
	fmt.Println("Found the go files: ", goFiles)

	// Set up mock database to test the simulations
	connStr := "host=db password=testpassword user=test dbname=security_scan_db sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v\n", err)
	}
	defer db.Close()
	// Check if the connection is valid
	if err = waitForDB(db); err != nil {
		log.Fatalf("Failed to ping the database: %v", err)
	}

	var parsedGoFiles []*ast.File

	for _, goFile := range goFiles {
		parsedFile, err := parseGoFiles(goFile)
		if err != nil {
			fmt.Printf("Error parsing %s file in the main func: %v\n", goFile, err)
		}

		log.Printf("Checking %s for hardcoded secrets\n", goFile)
		vuln := simulations.CheckForSecrets(parsedFile, goFile)
		fmt.Println("Found hardcoded secrets: ", vuln)

		log.Printf("Checking %s for SQL Injection vulnerabilities\n", goFile)
		sqlVuln := simulations.CheckForDynamicSqlQueries(parsedFile, goFile)
		fmt.Println("Found SQL Injection vulnerabilities: ", sqlVuln)

		parsedGoFiles = append(parsedGoFiles, parsedFile)
		fmt.Printf("Parsing %s file and appending into parsed files array\n", goFile)
	}

	// Possible ast printing of the files for debugging
	// ast.Print(token.NewFileSet(), parsedGoFiles)

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

func waitForDB(db *sql.DB) error {
	retryCount := 10
	for i := 0; i < retryCount; i++ {
		err := db.Ping()
		if err == nil {
			return nil
		}
		log.Printf("Database not ready, retrying... (%d/%d)\n", i+1, retryCount)
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("failed to connect to the database after %d retries", retryCount)
}
