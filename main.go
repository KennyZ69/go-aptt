package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
)

func securityScan(target string) (string, error) {
	fmt.Printf("Running security scans on: %v\n", target)

	// Now check for vulnerabilities, possible exploitaitons, and make report messages with suggestions on fixes

	if target == "vulnerable-app" {
		return "Vulnerabilities detect in the target app", fmt.Errorf("vulnerable-app as target")
	}
	return "No vulnerabilities for now", nil
}

func main() {

	rootDir := "."
	goFiles, err := getGoFiles(rootDir)
	if err != nil {
		fmt.Printf("Error getting all the go files in the codebase: %v\n", err)
		return
	}
	fmt.Println("Found the go files: ", goFiles)

	var parsedGoFiles []*ast.File

	for _, goFile := range goFiles {
		parsedFile, err := parseGoFiles(goFile)
		if err != nil {
			fmt.Printf("Error parsing %s file in the main func: %v\n", goFile, err)
		}
		parsedGoFiles = append(parsedGoFiles, parsedFile)
		fmt.Printf("Parsing %s file and appending into parsed files array\n", goFile)
	}

	// Possible ast printing of the files for debugging
	// ast.Print(token.NewFileSet(), parsedGoFiles)

	// Pass target as a command-line argument for now
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go [target]")
		os.Exit(1)
	}

	target := os.Args[1]

	report, err := securityScan(target)
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
		if !d.IsDir() && (filepath.Ext(d.Name()) == ".go") {
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
	ast.Print(fset, node)
	return node, err
}
