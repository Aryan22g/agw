package main

import "github.com/Aryan22g/agw/internal/cli/auditcli"

// runAudit dispatches the audit subcommands. The implementation is shared
// with `agw audit`, so the two binaries cannot drift apart again.
func runAudit(args []string) error {
	return auditcli.Run("ags", args)
}
