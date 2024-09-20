package simulations

import (
	"database/sql"
	"fmt"
	"github.com/KennyZ69/go-aptt/types"
	"go/ast"
	"go/token"
)

func CheckForDynamicSqlQueries(node ast.Node, filename string) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		switch stmt := n.(type) {
		case *ast.AssignStmt:
			for _, rhs := range stmt.Rhs {
				if call, ok := rhs.(*ast.CallExpr); ok {
					if call.Fun == nil {
						return true
					}
					// Look for database-related function calls
					if ident, ok := call.Fun.(*ast.Ident); ok && ident.Name == "Exec" || ident.Name == "Query" {
						if call.Args == nil {
							return true
						}
						// Check for string concatenation in the SQL query
						for _, arg := range call.Args {
							if binaryExpr, ok := arg.(*ast.BinaryExpr); ok {
								if binaryExpr.Op == token.ADD {
									vuln := types.Vulnerability{
										Name:        "Dynamic SQL Query Construction",
										Description: "Potential SQL injection vulnerability due to dynamic SQL query construction using string concatenation",
										File:        filename,
										Line:        binaryExpr.Pos(),
									}
									vulnerabilities = append(vulnerabilities, vuln)
								}
							}
						}
					}
				}
			}
		}
		return true
	})
	return vulnerabilities
}

func SimulateSQLInjection(db *sql.DB) []string {
	var results []string
	payloads := []string{
		"' OR 1=1; --",
		"' UNION SELECT null, null, null; --",
		"'; SELECT IF(1=1, sleep(5), 0); --",
		"'; DROP TABLE users; --",
		"' AND 1=1; --",
	}

	for _, payload := range payloads {
		injectedQuery := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", payload)
		fmt.Printf("Simulating SQL Injection with payload: %s\n", injectedQuery)

		_, err := db.Exec(injectedQuery)
		if err != nil {
			results = append(results, fmt.Sprintf("SQL Injection succeeded with payload: %s\n", payload))
		} else {
			results = append(results, fmt.Sprintf("SQL Injection failed with payload: %s\n", payload))
		}
	}
	return results
}
