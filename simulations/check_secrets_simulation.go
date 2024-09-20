package simulations

import (
	"go/ast"
	"go/token"
	"regexp"

	"github.com/KennyZ69/go-aptt/types"
)

func CheckForSecrets(node ast.Node, fileName string) []types.Vulnerability {
	var vulnerabilities []types.Vulnerability
	secretPattern := regexp.MustCompile(`(?i)(password|apikey|token|secret)[^=]*=("|')\w+("|')`)

	// Inspect the AST for hardcoded secrets
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
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
