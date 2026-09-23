package authz_test

import (
	"testing"

	"github.com/Aryan22g/agw/internal/gateway/authz"
)

// TestWildcardInAnUnsupportedPositionIsRejected.
//
// The matcher supports a wildcard alone or as a trailing ".*" on the dot
// boundary. Anything else used to load cleanly and then match nothing, for
// ever. On an allow rule that is a confusing outage; on a deny rule it is a
// guardrail the operator believes they have and does not.
//
// Found while building the MCP enforcement point, where "mcp.tool.search_*"
// looked obviously correct and silently never matched.
func TestWildcardInAnUnsupportedPositionIsRejected(t *testing.T) {
	bad := []string{
		"mcp.tool.search_*",
		"github.issue*",
		"*.create",
		"a.*.b",
		"github.*.*",
		"*github.issue.create",
	}

	for _, pattern := range bad {
		t.Run(pattern, func(t *testing.T) {
			p := &authz.Policy{
				Tenant:  "acme",
				Version: "1",
				Rules: []authz.Rule{{
					ID:      "r",
					Effect:  authz.EffectDeny,
					Agents:  []string{"*"},
					Actions: []string{pattern},
				}},
			}
			if err := p.Validate(); err == nil {
				t.Errorf("%q was accepted but would never match anything", pattern)
			}
		})
	}
}

func TestSupportedWildcardsStillValidate(t *testing.T) {
	good := []string{"*", "github.issue.*", "github.issue.create", "mcp.tool.*"}

	for _, pattern := range good {
		t.Run(pattern, func(t *testing.T) {
			p := &authz.Policy{
				Tenant:  "acme",
				Version: "1",
				Rules: []authz.Rule{{
					ID:      "r",
					Effect:  authz.EffectAllow,
					Agents:  []string{"*"},
					Actions: []string{pattern},
				}},
			}
			if err := p.Validate(); err != nil {
				t.Errorf("%q was rejected: %v", pattern, err)
			}
		})
	}
}

func TestResourceWildcardPositionIsChecked(t *testing.T) {
	for _, pattern := range []string{"acme*", "*/app", "a/*/b"} {
		t.Run(pattern, func(t *testing.T) {
			p := &authz.Policy{
				Tenant:  "acme",
				Version: "1",
				Rules: []authz.Rule{{
					ID:        "r",
					Effect:    authz.EffectAllow,
					Agents:    []string{"*"},
					Actions:   []string{"*"},
					Resources: []string{pattern},
				}},
			}
			if err := p.Validate(); err == nil {
				t.Errorf("resource pattern %q was accepted but would never match", pattern)
			}
		})
	}
}
