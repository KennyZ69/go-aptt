package tests

import (
	"go/parser"
	"go/token"
	"testing"

	"github.com/KennyZ69/go-aptt/simulations/inter"
	"github.com/stretchr/testify/assert"
)

// TestCheckForDynamicSqlQueries checks the AST for vulnerabilities
func TestCheckForDynamicSqlQueries(t *testing.T) {
	tests := []struct {
		name          string
		sourceCode    string
		expectedVulns int
	}{
		{
			name: "Dynamic SQL Query Construction",
			sourceCode: `
				package main
				func query(db *sql.DB, username string) {
					query := fmt.Sprintf("SELECT * FROM users WHERE username = " + username)
					db.Exec(query)
				}
			`,
			expectedVulns: 1,
		},
		{
			name: "Safe SQL Query Construction",
			sourceCode: `
				package main
				func query(db *sql.DB, username string) {
					query := "SELECT * FROM users WHERE username = $1"
					db.Exec(query, username)
				}
			`,
			expectedVulns: 0,
		},
		{
			name: "Nil Handling",
			sourceCode: `
				package main
				func query(db *sql.DB) {
					db.Exec(nil)
				}
			`,
			expectedVulns: 0, // Test should not panic here
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Parse the source code
			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, "", test.sourceCode, parser.AllErrors)
			assert.NoError(t, err)

			// Run the SQL injection check
			vulnerabilities := inter.CheckForDynamicSqlQueries(node, "test.go")

			// Assert the number of vulnerabilities
			assert.Equal(t, test.expectedVulns, len(vulnerabilities))
		})
	}
}

func TestCheckForSecrets(t *testing.T) {
	tests := []struct {
		name          string
		source        string
		expectedVulns int
		// expectedNames []string
	}{
		{
			name: "Hardcoded Password Detected",
			source: `
				package main
				func main() {
					password := "supersecretpassword"
				}
			`,
			expectedVulns: 1,
			// expectedNames: []string{"Hardcoded Secret"},
		},
		{
			name: "Hardcoded API Key Detected",
			source: `
				package main
				func main() {
					apiKey := "1234567890abcdef"
				}
			`,
			expectedVulns: 1,
			// expectedNames: []string{"Hardcoded Secret"},
		},
		{
			name: "No Hardcoded Secrets",
			source: `
				package main
				func main() {
					nonSensitive := "some harmless string"
				}
			`,
			expectedVulns: 0,
			// expectedNames: nil,
		},
		{
			name: "Secret in Non-String Expression",
			source: `
				package main
				func main() {
					password := 12345
				}
			`,
			expectedVulns: 1,
			// expectedNames: nil,
		},
		{
			name: "Secret in Complex Expression",
			source: `
				package main
				func main() {
					complexPassword := "password=" + "something"
				}
			`,
			expectedVulns: 1,
			// expectedNames: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fset := token.NewFileSet()
			node, err := parser.ParseFile(fset, "", test.source, parser.AllErrors)
			if err != nil {
				t.Fatalf("Error parsing source: %v", err)
			}

			vulns := inter.CheckForSecrets(node, "main.go")

			if len(vulns) != test.expectedVulns {
				t.Errorf("Expected %d vulnerabilities, got %d", test.expectedVulns, len(vulns))
			}

			// for i, vuln := range vulns {
			// 	if vuln.Name != test.expectedNames[i] {
			// 		t.Errorf("Expected vulnerability name %s, got %s", test.expectedNames[i], vuln.Name)
			// 	}
			// }
		})
	}
}

func TestCheckForXSS(t *testing.T) {
	tests := []struct {
		name          string
		code          string
		expectedVulns int
	}{
		{
			name: "Unsafe rendering with user input - possible XSS",
			code: `
				package main

				import (
					"fmt"
					"net/http"
				)

				func handler(w http.ResponseWriter, r *http.Request) {
					input := r.FormValue("input")
					fmt.Fprintf(w, input) // Possible XSS
				}
			`,
			expectedVulns: 1,
		},
		{
			name: "Safe rendering with HTML escaping",
			code: `
				package main

				import (
					"fmt"
					"net/http"
					"html"
				)

				func handler(w http.ResponseWriter, r *http.Request) {
					input := r.FormValue("input")
					escapedInput := html.EscapeString(input)
					fmt.Fprintf(w, escapedInput) // Safe usage
				}
			`,
			expectedVulns: 0,
		},
		{
			name: "User input not used in rendering",
			code: `
				package main

				import "net/http"

				func handler(w http.ResponseWriter, r *http.Request) {
					input := r.FormValue("input")
					_ = input // Not used
				}
			`,
			expectedVulns: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs := token.NewFileSet()
			node, err := parser.ParseFile(fs, "", tt.code, parser.AllErrors)
			if err != nil {
				t.Fatalf("Failed to parse code: %v", err)
			}

			// Run the function to check for XSS vulnerabilities
			vulns := inter.CheckForXSSPossibilities(node, "test.go")

			// if len(vulns) == 0 {
			// 	t.Errorf("Expected vulnerabilities, but found none")
			// } else {
				for _, vuln := range vulns {
					t.Logf("Found vulnerability: %s at line %d", vuln.Description, vuln.Line)
				}
			// }
			// Check if the number of vulnerabilities matches the expected number
			if len(vulns) != tt.expectedVulns {
				t.Errorf("Expected %d vulnerabilities, but got %d", tt.expectedVulns, len(vulns))
			}
		})
	}
}
