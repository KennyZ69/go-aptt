package inter

import (
	"fmt"
	"log"

	"github.com/KennyZ69/go-aptt/types"
)

func Codebase_scan(target string) ([]types.Vulnerability, error) {
	log.Println("Starting the Codebase_Scan from: ", target)
	var vulns []types.Vulnerability

	goFiles, err := types.GetGoFiles(target)
	if err != nil {
		return nil, fmt.Errorf("Problem getting the go files in Codebase_scan: %v\n", err)
	}

	log.Println("Found files: ", goFiles)

	for _, file := range goFiles {
		log.Printf("Parsing %s\n", file)

		parsedFile, err := types.ParseGoFiles(file)
		if err != nil {
			return nil, fmt.Errorf("Problem parsing the go files in Codebase_scan: %v\n", err)
		}

		log.Println("Looking for hardcoded secrets in the file")
		// Checking for hardcoded secrets like api key, passwords etc...
		vulns = CheckForSecrets(parsedFile, file)
		if vulns == nil {
			log.Printf("No hardcoded secrets were found in %s\n", file)
		} else {
			log.Printf("Found hardcoded secrets in %s: %v\n", file, vulns)
		}
		vulns = append(vulns, CheckForDynamicSqlQueries(parsedFile, file)...)
	}

	// I should probably stop returning the vulnerabilites, just the errors
	log.Println("Security scan on the codebase ended, look for your reports in the reports directory")
	return vulns, nil
}
