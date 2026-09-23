// Command agw is the confinement plane: it is the only route a confined
// workload has to the network, it decides what that workload may reach, and
// it records every decision in a tamper-evident chain.
//
// It handles the case a cooperative control cannot: an agent that has root
// inside its sandbox and does not want to cooperate. Nothing here asks the
// agent to send its traffic anywhere; the network gives it no other route.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/Aryan22g/agw/internal/buildinfo"
	"github.com/Aryan22g/agw/internal/cli/auditcli"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "audit":
		err = auditcli.Run("agw", os.Args[2:])
	case "tail":
		err = auditcli.Run("agw", append([]string{"tail"}, os.Args[2:]...))
	case "policy":
		err = runPolicy(os.Args[2:])
	case "sidecar-init":
		err = runSidecarInit(os.Args[2:])
	case "suspend":
		// The incident-response name for the kill switch. Same operation.
		err = runRevoke(os.Args[2:])
	case "version", "--version":
		fmt.Println(buildinfo.String("agw"))
		return
	case "watch":
		err = runWatch(os.Args[2:])
	case "mcp":
		err = runMCP(os.Args[2:])
	case "run":
		err = runRun(os.Args[2:])
	case "proxy":
		err = runProxy(os.Args[2:])
	case "revoke":
		err = runRevoke(os.Args[2:])
	case "status":
		err = runStatus(os.Args[2:])
	case "keygen":
		err = runKeygen(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "agw: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}

	if err != nil {
		// Evidence that does not verify exits 2, distinct from 1 for "could
		// not run", so a pipeline gating on verification can tell a finding
		// from a broken step.
		var ee *auditcli.ExitError
		if errors.As(err, &ee) {
			if ee.Code == 1 {
				fmt.Fprintf(os.Stderr, "agw: %v\n", err)
			}
			os.Exit(ee.Code)
		}
		fmt.Fprintf(os.Stderr, "agw: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `agw -- confine AI agents, and prove what they did

Get started:
  agw init                       key + starter policy + what to run next

Record, rehearse, enforce, contain -- each rung works on its own:
  agw watch   [--policy FILE]    record OpenTelemetry from any agent as signed evidence;
                                 with --policy, report what enforcement WOULD block
  agw mcp     --policy FILE --agent ID --upstream URL
                                 enforce policy on MCP tool calls
  agw run     --policy FILE -- COMMAND [ARGS...]
                                 run a command contained: it reaches only what policy
                                 allows, even as root (Linux)
  agw proxy   --policy FILE --listen ADDR --evidence FILE [--workload ID=ADDR ...]
                                 the enforcement point, for Docker / Kubernetes / VMs
  agw sidecar-init [--proxy-uid 1337] [--proxy-port 8080]
                                 confine a workload sharing the proxy's network namespace
                                 (Kubernetes pod, docker --network container:X)

Evidence -- verification needs only the file and a public key:
  agw audit verify  EVIDENCE --key PUB [--anchor KEPT]
  agw audit show    EVIDENCE [--agent ID] [--denied] [--would-deny] [--since 1h]
  agw tail          EVIDENCE [--agent ID]
  agw audit export  EVIDENCE --out BUNDLE [--from T --to T]
  agw audit verify-bundle BUNDLE --key PUB

Policy:
  agw policy lint     FILE...
  agw policy explain  --policy FILE --workload ID HOST[:PORT]
  agw policy suggest  EVIDENCE [--workload ID] [--out FILE]

Operations:
  agw suspend --workload ID [--reason TEXT]   kill switch: refuse and cut open connections
  agw status                                  allow/deny counts and chain head
  agw keygen  --out FILE                      a checkpoint key in a location you choose
  agw version

Checkpoint keys default to ~/.agw/checkpoint.key (created on first use).
Pass --key FILE, --key unix:/path/to/ags-signd.sock for separate custody,
or --key none. The admin interface is a unix socket, never a network port:
a confined workload must not be able to reach its own kill switch.

Exit status: 0 ok, 1 error, 2 evidence did not verify.
`)
}

func flagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	return fs
}
