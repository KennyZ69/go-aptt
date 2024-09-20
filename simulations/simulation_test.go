package simulations

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
