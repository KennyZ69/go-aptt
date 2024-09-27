package tests

import (
	"go/parser"
	"go/token"
	"log"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
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
					query := "SELECT * FROM users WHERE username = '" + username + "'"
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
			vulnerabilities := CheckForDynamicSqlQueries(node, "test.go")

			// Assert the number of vulnerabilities
			assert.Equal(t, test.expectedVulns, len(vulnerabilities))
		})
	}
}

// TestSimulateSQLInjection tests SQL injection simulation
func TestSimulateSQLInjection(t *testing.T) {
	// Create a mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to open a mock database: %s", err)
	}
	defer db.Close()

	// Setup expectations for SQL executions
	mock.ExpectExec("SELECT \\* FROM users WHERE username =").WillReturnResult(sqlmock.NewResult(1, 1))

	// Run the simulation
	results := SimulateSQLInjection(db)
	// try to print the results to check if it is alright
	log.Println(results)

	// Assert that there are results
	assert.NotNil(t, results)
	assert.NotEmpty(t, results)

	// Verify all expectations were met
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("there were unfulfilled expectations: %s", err)
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

			vulns := CheckForSecrets(node, "main.go")

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
