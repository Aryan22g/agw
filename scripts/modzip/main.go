// Command modzip checks that the repository can be packaged as a Go module
// zip -- the step `go install github.com/Aryan22g/agw/cmd/agw@vX`
// performs on the module proxy. One file name it refuses (v0.1.0 had two,
// with an em dash) breaks `go install` for every user of that tag, and a
// published tag cannot be repaired. CI runs this on every change.
//
// It is its own module so golang.org/x/mod stays out of the product's
// dependencies.
//
//	go -C scripts/modzip run . ../..
package main

import (
	"fmt"
	"os"

	"golang.org/x/mod/zip"
)

func main() {
	dir := "."
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}
	files, err := zip.CheckDir(dir)
	for _, f := range files.Invalid {
		fmt.Printf("::error file=%s::not allowed in a Go module zip: %v\n", f.Path, f.Err)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "modzip:", err)
		os.Exit(1)
	}
	fmt.Printf("module zip ok: %d files\n", len(files.Valid))
}
