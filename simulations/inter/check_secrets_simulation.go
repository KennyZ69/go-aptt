package inter

import (
	"fmt"
	"go/ast"
	"go/token"
	"log"
	"regexp"
	"strings"

	"github.com/KennyZ69/go-aptt/types"
)

func CheckForSecrets(node *ast.File, fileName string) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability
	secretPattern := regexp.MustCompile(`(?i)(pwd|password|apikey|token|secret)[^=]*=("|')\w+("|')`)

	// Inspect the AST for hardcoded secrets
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			// log.Println("Node is nil in CheckForHardcodedSecrets")
			return false
		}

		switch x := n.(type) {

		// switch x := node.(type) {
		case *ast.AssignStmt:
			for _, rhs := range x.Rhs {
				if basicLit, ok := rhs.(*ast.BasicLit); ok && basicLit.Kind == token.STRING {
					if secretPattern.MatchString(basicLit.Value) {
						vuln := types.Vulnerability{
							Name:        "Hardcoded Secret",
							Description: "Potential hardcoded secret found",
							File:        fileName,
							Line:        basicLit.Pos(),
						}
						vulnerabilities = append(vulnerabilities, vuln)
					}
				}
			}
		}
		return true
	})
	return vulnerabilities
}

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

func CheckForXSSPossibilities(node *ast.File, filename string) []types.Vulnerability {
	var vulns []types.Vulnerability
	userControlledArgs := make(map[string]bool)
	log.Println("Starting the scan for possible XSS inputs")
	// possibleDangerFuncs := regexp.MustCompile(`(?i)(Fprintf|Sprintf|Write)`)

	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
		//TODO:Finish this case where it is assignment so that I can then write tests to figure this out
		case *ast.CallExpr:
			if types.IsRenderDirectly(x) {
				for _, arg := range x.Args {
					if ident, ok := arg.(*ast.Ident); ok && userControlledArgs[ident.Name] && !types.IsSanitizedUserInput(x) {
						vulns = append(vulns, types.Vulnerability{
							Name:        "Possible XSS vulnerability coded in the codebase",
							Description: "User input being used directly to render in the HTML context without sanitization",
							File:        filename,
							Line:        x.Pos(),
						},
						)
					}
				}
			}
		}
		return true
	})
	return vulns
}
