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
	// secretPattern := regexp.MustCompile(`(?i)(pwd|password|apikey|token|secret|api_key|apiKey|passwd)[^=]*=("|')\w+("|')`)
	secretPattern := regexp.MustCompile(`(?i)(pwd|password|apikey|token|secret|api_key|apiKey|passwd)$`)

	// Inspect the AST for hardcoded secrets
	ast.Inspect(node, func(n ast.Node) bool {
		if n == nil {
			// log.Println("Node is nil in CheckForHardcodedSecrets")
			return false
		}

		switch x := n.(type) {

		// switch x := node.(type) {
		case *ast.AssignStmt:
			fmt.Println("Found the node as assign statement")
			for index, rhs := range x.Rhs {
				fmt.Println("Checking the right hand side")
				if basicLit, ok := rhs.(*ast.BasicLit); ok && (basicLit.Kind == token.STRING || basicLit.Kind == token.INT) {
					fmt.Println("Found the basic lit and its kind")
					lhs := x.Lhs[index]
					fmt.Println("Checking the left hand side")
					if ident, ok := lhs.(*ast.Ident); ok {
						fmt.Println("Got the identifier for the lhs")
						fmt.Println(ident.Name)
						if secretPattern.MatchString(ident.Name) || strings.Contains(basicLit.Value, "password=") {
							fmt.Println("Identifier name matching the secret pattern")
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
			// case *ast.CallExpr:
			log.Println("CheckDynamicQueries checking the assing statement")
			for _, rhs := range stmt.Rhs {
				fmt.Println("Looping for the right hand side of the assign statement")
				if call, ok := rhs.(*ast.CallExpr); ok {
					fmt.Println("Getting the call expression from the statement")
					if call.Fun == nil {
						log.Println("Call.Fun is nil in CheckDynamicQueries")
						return false
					}

					// TODO: It should probably be *selectorExpr so should handle it that way !
					switch fun := call.Fun.(type) {
					case *ast.Ident:
						fmt.Println("Watching for the type of the function -> ast.Ident")
						if fun.Name == "Exec" || fun.Name == "Query" {
							fmt.Println("For some reason it found function call for db without the db")
							return false
						}

					case *ast.SelectorExpr:
						fmt.Println("Watching for the type of function -> selector expression")
						if ident, ok := fun.X.(*ast.Ident); ok {
							if ident.Name == "db" || ident.Name == "DB" {
								fmt.Println("There is the db before it")
								if fun.Sel.Name == "Exec" || fun.Sel.Name == "Query" {
									fmt.Println("The func is either Exec or Query")
									if len(call.Args) >= 1 { // Check if arguments are passed
										fmt.Println("Length of arguments into the function is greater than 1")
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
											log.Println("Found a dynamic query that could be a problem")
											vulnerabilities = append(vulnerabilities, vuln)
											// }
										}
									}

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
			for _, rhs := range x.Rhs {
				if types.IsUserControlledInput(rhs) {
					for _, lhs := range x.Lhs {
						if ident, ok := lhs.(*ast.Ident); ok {
							userControlledArgs[ident.Name] = true
						}
					}
				}
			}
		case *ast.CallExpr:
			if types.IsRenderingDirectly(x) {
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
