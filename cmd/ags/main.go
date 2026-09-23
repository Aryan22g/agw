// Command ags is the AGS1 developer CLI.
//
// It covers the tasks a developer or operator needs outside application code:
// generating agent and gateway keys, inspecting what a request would sign, and
// checking an implementation against the conformance vectors.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Aryan22g/agw/internal/buildinfo"
	"github.com/Aryan22g/agw/internal/cli/auditcli"
)

const usage = `ags - AGS1 request signing and evidence CLI

Usage:
  ags audit verify  Prove an evidence log was not altered (run this as an auditor)
  ags audit show    Query decisions from an evidence log
  ags audit tail    Follow an evidence log as it is written
  ags audit export  Package evidence for an auditor
  ags audit verify-bundle  Verify an exported evidence bundle
  ags doctor        Diagnose a local agent setup
  ags keygen        Generate an Ed25519 keypair and its AGS1 key id
  ags sign          Sign a request and print the signature base (debugging)
  ags verify        Verify a signed request against a public key
  ags thumbprint    Derive an AGS1 key id from a public key
  ags version       Print the build

Run 'ags <command> -h' for command flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "audit":
		err = runAudit(os.Args[2:])
	case "doctor":
		err = runDoctor(os.Args[2:])
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "sign":
		err = runSign(os.Args[2:])
	case "verify":
		err = runVerify(os.Args[2:])
	case "thumbprint":
		err = runThumbprint(os.Args[2:])
	case "version", "--version":
		fmt.Println(buildinfo.String("ags"))
		return
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "ags: unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		// A verification failure exits 2, distinct from 1 for "could not
		// run", so a pipeline can tell a finding from a broken step.
		var ee *auditcli.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.Code)
		}
		fmt.Fprintf(os.Stderr, "ags: %v\n", err)
		os.Exit(1)
	}
}

// flagSet builds a FlagSet that prints its own usage on error.
func flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ags %s [flags]\n\nFlags:\n", name)
		fs.PrintDefaults()
	}
	return fs
}

func mustAbsent(v, name string) error {
	if strings.TrimSpace(v) == "" {
		return fmt.Errorf("-%s is required", name)
	}
	return nil
}
