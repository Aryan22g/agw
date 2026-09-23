package sidecar

import (
	"strings"
	"testing"
)

func TestRulesAreDefaultDenyWithTheProxyAsTheOnlyWayOut(t *testing.T) {
	r, err := Rules(Config{ProxyUID: 1337, ProxyPort: 8080, AllowLoopbackPorts: []int{8900}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"policy drop;",
		"meta skuid 1337 accept",
		`oif "lo" tcp dport { 8080, 8900 } accept`,
		"ct state established,related accept",
		"counter name refused_direct drop",
		"delete table inet agw_sidecar", // idempotent replace in one transaction
	} {
		if !strings.Contains(r, want) {
			t.Errorf("ruleset lacks %q:\n%s", want, r)
		}
	}
	// The proxy exception must come before the final drop, and nothing may
	// accept by destination address: an address allowlist here would be a
	// second policy, unrecorded.
	if strings.Index(r, "skuid") > strings.Index(r, "refused_direct drop") {
		t.Error("the proxy exception is after the drop")
	}
	if strings.Contains(r, "ip daddr") || strings.Contains(r, "ip6 daddr") {
		t.Error("the ruleset accepts by destination address; destinations belong to the proxy's policy")
	}
}

func TestRootCannotBeTheProxyUID(t *testing.T) {
	if _, err := Rules(Config{ProxyUID: 0, ProxyPort: 8080}); err == nil {
		t.Fatal("proxy UID 0 accepted: a root workload would share the proxy's exception")
	}
	if _, err := Rules(Config{ProxyUID: 1337, ProxyPort: 70000}); err == nil {
		t.Fatal("port out of range accepted")
	}
}
