package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const starterEgressPolicy = `# Egress policy: which destinations each confined workload may reach.
#
# Everything not listed is denied. There is no wildcard workload and no way to
# switch off the structural denials (cloud metadata, link-local, NAT64) from
# this file. Check changes with:  agw policy lint agw-policy.yaml
#
# Rehearse before enforcing -- nothing is blocked in this mode:
#   agw watch --policy agw-policy.yaml
version: "1"

workloads:
  # The id must match the agent's name: its OpenTelemetry service.name
  # (OTEL_SERVICE_NAME) under agw watch, or --workload under agw run.
  - id: my-agent
    allow:
      - host: pypi.org
        ports: [443]
        note: package index metadata
      - host: files.pythonhosted.org
        ports: [443]
        note: package downloads
      # - host: api.github.com
      #   ports: [443]
      #   note: repository access

# Narrow CIDRs exempted from the private-address denial, e.g. an internal
# service at 10.20.30.0/24. Link-local and NAT64 space can never be exempted.
permit_private: []
`

// runInit sets up a working directory for the first five minutes.
//
// It exists because every rung of the adoption ladder needs the same two
// things -- a signing key and a policy -- and a new user should not have to
// learn keygen flags and policy syntax before seeing anything work. It never
// overwrites: re-running it is safe, and a file someone has edited is theirs.
func runInit(args []string) error {
	dir := "."
	if len(args) > 0 {
		dir = args[0]
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	ck, err := resolveCheckpointKey("")
	if err != nil {
		return err
	}
	defer ck.Close()

	policyPath := filepath.Join(dir, "agw-policy.yaml")
	wrote, err := writeIfAbsent(policyPath, starterEgressPolicy)
	if err != nil {
		return err
	}

	fmt.Printf("agw is set up.\n\n")
	fmt.Printf("  checkpoint key  %s\n", ck.Source)
	if ck.PubPath != "" {
		fmt.Printf("  public key      %s  (give this to whoever verifies your evidence)\n", ck.PubPath)
	}
	if wrote {
		fmt.Printf("  egress policy   %s  (edit the workload id and destinations)\n", policyPath)
	} else {
		fmt.Printf("  egress policy   %s  (already existed; left as it was)\n", policyPath)
	}

	fmt.Print(`
Pick the rung that fits. Each works on its own; stop at any of them.

  0  Record    -- signed evidence of what your agents do. 5 minutes, no risk.
       agw watch
       then, in the agent's environment, the three exports it prints.

  1  Rehearse  -- see what a policy WOULD block. Nothing is blocked.
       agw watch --policy agw-policy.yaml
       agw audit show agw-evidence-*.jsonl --would-deny

  2  Enforce tool calls -- refuse MCP tool calls policy does not allow.
       agw mcp --upstream http://localhost:3000/mcp --policy-dir DIR --tenant T --agent my-agent

  3  Contain   -- the agent cannot reach anything policy does not allow,
                  even with root. Linux; needs root to build the sandbox.
       sudo agw run --policy agw-policy.yaml -- python agent.py

Check any evidence file, anywhere, with only the public key:
  agw audit verify EVIDENCE.jsonl --key ` + orPlaceholder(ck.PubPath) + `
`)
	return nil
}

func orPlaceholder(p string) string {
	if p == "" {
		return "CHECKPOINT.pub"
	}
	return p
}

func writeIfAbsent(path, content string) (bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if errors.Is(err, os.ErrExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return false, err
	}
	return true, f.Close()
}
