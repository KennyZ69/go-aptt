package simulations

import (
	"go/ast"
	"go/token"
	"log"
	"regexp"

	"github.com/KennyZ69/go-aptt/types"
)

func CheckForSecrets(node *ast.File, fileName string) []types.Vulnerability {
	log.Printf("Node type: %T\n", node)
	var vulnerabilities []types.Vulnerability
	secretPattern := regexp.MustCompile(`(?i)(password|apikey|token|secret)[^=]*=("|')\w+("|')`)

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
