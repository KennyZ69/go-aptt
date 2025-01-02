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
	secretPattern := regexp.MustCompile(`(?i)(pwd|password|apikey|token|secret|api_key|apiKey|passwd)`)

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
						if secretPattern.MatchString(ident.Name) {
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
		unsafeCalls := make(map[string]bool)
		userControlledInputs := make(map[string]bool)
		// skip node if it is nil, also if the function call or arguments (or each individual argument) is nil, skip them

		if n == nil {
			// log.Println("Node is nil in CheckDynamicQueries")
			return false
		}
		switch stmt := n.(type) {

		// TODO: Probably I will need to do this similarly to the xss checking so using a map etc...
		case *ast.AssignStmt:
			fmt.Println("Looking at an assignment statement")
			// TODO: Have to check whether it is unsafe user controlled input
			for index, rhs := range stmt.Rhs {
				fmt.Println("Looking at rhs of an assignstmt")
				if types.IsUserControlledInput(rhs) {
					fmt.Println("Is user controlled input and unsafe query construction")
					lhs := stmt.Lhs[index]
					if ident, ok := lhs.(*ast.Ident); ok {
						userControlledInputs[ident.Name] = true
					}
				}
				if types.UnsafeSqlConstruction(rhs) {
					fmt.Println("Is unsafe sql call")
					lhs := stmt.Lhs[index]
					if ident, ok := lhs.(*ast.Ident); ok {
						unsafeCalls[ident.Name] = true
					}
				}
			}

		case *ast.CallExpr:
			fmt.Println("Looking at the statement as a call expression")
			if fun, ok := stmt.Fun.(*ast.SelectorExpr); ok {
				fmt.Println("Got the fun: " + fun.Sel.Name)
				if ident, ok := fun.X.(*ast.Ident); ok {
					fmt.Println("Got the identifier: " + ident.Name)
					if (ident.Name == "db" || ident.Name == "DB" || ident.Name == "sql.DB" || ident.Name == "tx" || ident.Name == "stmt") && (fun.Sel.Name == "Query" || fun.Sel.Name == "Exec" || fun.Sel.Name == "QueryRow" || fun.Sel.Name == "Prepare") {
						for _, arg := range stmt.Args {
							switch argExpr := arg.(type) {
							case *ast.BasicLit:
								// Direct string argument without parameterization
								fmt.Println("Argument is basic lit => direct string")
								if argExpr.Kind == token.STRING && !(strings.Contains(argExpr.Value, "?") || strings.Contains(argExpr.Value, "$")) {
									vulnerabilities = append(vulnerabilities, types.Vulnerability{
										Name:        "Possible SQL Injection",
										Description: "SQL query may be vulnerable to SQL injection due to lack of parameterization",
										File:        filename,
										Line:        argExpr.Pos(),
									})
								}
							case *ast.BinaryExpr:
								// Detect string concatenation
								if argExpr.Op == token.ADD {
									vulnerabilities = append(vulnerabilities, types.Vulnerability{
										Name:        "Possible SQL Injection",
										Description: "SQL query is constructed using string concatenation, which may be vulnerable to SQL injection",
										File:        filename,
										Line:        argExpr.Pos(),
									})
								}
							case *ast.CallExpr:
								// Check if fmt.Sprintf or similar is used
								if fmtFunc, ok := argExpr.Fun.(*ast.SelectorExpr); ok {
									if pkg, ok := fmtFunc.X.(*ast.Ident); ok && pkg.Name == "fmt" && fmtFunc.Sel.Name == "Sprintf" {
										vulnerabilities = append(vulnerabilities, types.Vulnerability{
											Name:        "Possible SQL Injection",
											Description: "SQL query is constructed using fmt.Sprintf, which may be vulnerable to SQL injection",
											File:        filename,
											Line:        argExpr.Pos(),
										})
									}
								}
							case *ast.Ident:
								if unsafeCalls[argExpr.Name] || userControlledInputs[argExpr.Name] {
									vulnerabilities = append(vulnerabilities, types.Vulnerability{
										Name:        "Possible SQL Injection",
										Description: "SQL query is constructed using variable which was not properly sanitized from possible sql injection vulnerability",
										File:        filename,
										Line:        argExpr.Pos(),
									})
								}
								// Further analysis may be needed to determine if the variable is user-controlled
								// You could add a map to track variable assignments and trace them back to user input
							}
						}
					}
				}
			}
		}

		// case

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
			fmt.Println("Looking at the node as assign statement")
			for index, rhs := range x.Rhs {
				fmt.Println("Looking at the right hand side")
				// if types.IsUserControlledInput(rhs) {
				isUControlInput := types.IsUserControlledInput(rhs)
				if isUControlInput {
					fmt.Println("Found out it is user controlled input")
					lhs := x.Lhs[index]
					if ident, ok := lhs.(*ast.Ident); ok {
						userControlledArgs[ident.Name] = true
					}
				}
			}
		case *ast.CallExpr:
			fmt.Println("Looking at the node as call expression")
			if types.IsRenderingDirectly(x) {
				fmt.Println("Found out it is rendering directly into html without sanitization")
				for _, arg := range x.Args {
					fmt.Println("Looking at the arguments")
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
