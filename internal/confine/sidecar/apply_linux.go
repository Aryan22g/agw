//go:build linux

package sidecar

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// Apply installs the ruleset in the current network namespace. It needs
// CAP_NET_ADMIN, which the init step has and the workload must not.
func Apply(c Config) error {
	rules, err := Rules(c)
	if err != nil {
		return err
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sidecar: nft: %v: %s", err, strings.TrimSpace(out.String()))
	}
	return nil
}

// Refused reports how many packets the rules have dropped: attempts to leave
// without going through the proxy.
func Refused() (uint64, error) {
	out, err := exec.Command("nft", "list", "counter", "inet", Table, "refused_direct").CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("sidecar: %v: %s", err, strings.TrimSpace(string(out)))
	}
	var packets uint64
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "packets" && i+1 < len(fields) {
			fmt.Sscan(fields[i+1], &packets)
		}
	}
	return packets, nil
}
