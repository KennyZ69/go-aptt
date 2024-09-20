package types

import "go/token"

type Vulnerability struct {
	Name        string
	Description string
	File        string
	// Line  int
	Line token.Pos
}
