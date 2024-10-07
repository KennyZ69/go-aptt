package types

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
)

type Vulnerability struct {
	Name        string
	Description string
	File        string
	// Line  int
	Line token.Pos
}

func GetGoFiles(root string) ([]string, error) {
	var goFiles []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (filepath.Ext(d.Name()) == ".go") && !strings.Contains(d.Name(), "_test.go") && !strings.Contains(d.Name(), "_simulation.go") && !strings.Contains(d.Name(), "_scan.go") {
			goFiles = append(goFiles, path)
		}
		return nil
	})
	return goFiles, err
}

func ParseGoFiles(filePath string) (*ast.File, error) {
	fset := token.NewFileSet()
	// parse the go file
	node, err := parser.ParseFile(fset, filePath, nil, parser.AllErrors)
	if err != nil {
		return nil, fmt.Errorf("Error parsing the %s file: %v\n", filePath, err)
	}

	if node == nil {
		return nil, fmt.Errorf("Parsed file got nil nodes: %s; report: %v\n", filePath, err)
	}
	// Print the AST (for debugging purposes)
	fmt.Printf("Parsed AST for %s:\n", filePath)

	// Possible ast printing of the files for debugging
	// ast.Print(fset, node)
	return node, err
}

func IsUserControlledInput(expr ast.Expr) bool {
	fmt.Println("Running the IsUserControlledInput function from checking for xss possibilities")
	switch e := expr.(type) {
	case *ast.SelectorExpr:
		fmt.Println("It is selector expression")
		// if ident, ok := e.X.(*ast.Ident); ok && (ident.Name == "req" || ident.Name == "r") {
		if ident, ok := e.X.(*ast.Ident); ok {
			fmt.Println(ident.Name)
			if e.Sel.Name == "FormValue" || e.Sel.Name == "Query" || e.Sel.Name == "Body" || e.Sel.Name == "PostForm" {
				return true
			}
		}
	case *ast.CallExpr:
		fmt.Println("It is call expression")
		if fun, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := fun.X.(*ast.Ident); ok && (pkg.Name == "r" || pkg.Name == "req" || pkg.Name == "request") && (fun.Sel.Name == "Query" || fun.Sel.Name == "FormValue" || fun.Sel.Name == "Body" || fun.Sel.Name == "PostForm") {
				return true
			}
		}	
	}
	return false
}

func IsSanitizedUserInput(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.CallExpr:
		if fun, ok := e.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := fun.X.(*ast.Ident); ok && (pkg.Name == "html" && fun.Sel.Name == "EscapeString") || (pkg.Name == "url" && fun.Sel.Name == "QueryEscape" || fun.Sel.Name == "PathEscape") || (pkg.Name == "strings" && fun.Sel.Name == "ReplaceAll") || (pkg.Name == "json" && fun.Sel.Name == "Marshal") {
				return true
			}
		}
	}
	return false
}

func IsRenderingDirectly(call *ast.CallExpr) bool {
	if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
		if ident, ok := fun.X.(*ast.Ident); ok {
			if (ident.Name == "fmt" && (fun.Sel.Name == "Fprintf" || fun.Sel.Name == "Sprintf")) || (ident.Name == "w" && fun.Sel.Name == "Write") {
				return true
			}
		}
	}
	return false
}

// func TestFunc() {
// 	pwd := "1234"
// 	fmt.Fprintf(io.MultiWriter(), pwd)
// }
