package simulations

import (
	"database/sql"
	"fmt"
	"go/ast"
	"log"
	"strings"

	"github.com/KennyZ69/go-aptt/types"
)

func CheckForDynamicSqlQueries(node *ast.File, filename string) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability
	ast.Inspect(node, func(n ast.Node) bool {
		// skip node if it is nil, also if the function call or arguments (or each individual argument) is nil, skip them

		if n == nil {
			// log.Println("Node is nil in CheckDynamicQueries")
			return false
		}
		switch stmt := n.(type) {

		// switch stmt := node.(type) {

		case *ast.AssignStmt:
			for _, rhs := range stmt.Rhs {
				if call, ok := rhs.(*ast.CallExpr); ok {
					if call.Fun == nil {
						log.Println("Call.Fun is nil in CheckDynamicQueries")
						return false
					}

					// TODO: It should probably be *selectorExpr so should handle it that way !
					switch fun := call.Fun.(type) {
					case *ast.Ident:
						if fun.Name == "Exec" || fun.Name == "Query" {
							fmt.Println("For some reason it found function call for db without the db")
							return false
						}

					case *ast.SelectorExpr:
						if fun.Sel.Name == "Exec" || fun.Sel.Name == "Query" {
							if len(call.Args) > 1 { // Check if arguments are passed
								// Ensure the SQL query has placeholders
								if basicLit, ok := call.Args[0].(*ast.BasicLit); ok && (strings.Contains(basicLit.Value, "?") || strings.Contains(basicLit.Value, "$")) {
									vuln := types.Vulnerability{
										Name:        "Safe SQL Query",
										Description: "Query uses parameterized inputs",
										File:        filename,
										Line:        basicLit.ValuePos,
									}
									log.Println("SQL Queries are alright: report: ", vuln)
									return true
									// No vulnerabilities here, parameterized queries are safe
								} else {
									vuln := types.Vulnerability{
										Name:        "Non-Parameterized SQL Query",
										Description: "Potential SQL injection due to missing parameterized inputs",
										File:        filename,
										Line:        basicLit.ValuePos,
									}

									// Check for string concatenation in the SQL query
									// for _, arg := range call.Args {
									// 	if arg == nil {
									// 		return true
									// 	}
									// 	if binaryExpr, ok := arg.(*ast.BinaryExpr); ok {
									// 		if binaryExpr.Op == token.ADD {
									// 			vuln := types.Vulnerability{
									// 				Name:        "Dynamic SQL Query Construction",
									// 				Description: "Potential SQL injection vulnerability due to dynamic SQL query construction using string concatenation",
									// 				File:        filename,
									// 				Line:        binaryExpr.Pos(),
									// 			}
									vulnerabilities = append(vulnerabilities, vuln)
									// }
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
