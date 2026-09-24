package recorder_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Aryan22g/agw/internal/confine"
	"github.com/Aryan22g/agw/internal/recorder"
)

func evaluator(t *testing.T) *recorder.Evaluator {
	t.Helper()

	path := filepath.Join(t.TempDir(), "policy.yaml")
	body := `
version: "1"
workloads:
  - id: support-agent
    allow:
      - host: api.zendesk.com
        ports: [443]
      - host: "*.githubusercontent.com"
        ports: [443]
permit_private: []
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	p, err := confine.LoadPolicy(path)
	if err != nil {
		t.Fatalf("load policy: %v", err)
	}
	e, err := recorder.NewEvaluator(p)
	if err != nil {
		t.Fatalf("evaluator: %v", err)
	}
	return e
}

func TestShadowVerdicts(t *testing.T) {
	e := evaluator(t)

	tests := []struct {
		name        string
		obs         recorder.Observation
		wantVerdict string
		wantReason  string
	}{
		{
			name: "permitted https destination",
			obs: recorder.Observation{AgentID: "support-agent",
				Resource: "https://api.zendesk.com/tickets/42", Target: "api.zendesk.com"},
			wantVerdict: recorder.VerdictWouldAllow,
		},
		{
			name: "wildcard subdomain",
			obs: recorder.Observation{AgentID: "support-agent",
				Resource: "https://raw.githubusercontent.com/a/b", Target: "raw.githubusercontent.com"},
			wantVerdict: recorder.VerdictWouldAllow,
		},
		{
			name: "destination not in the allowlist",
			obs: recorder.Observation{AgentID: "support-agent",
				Resource: "https://api.stripe.com/v1/refunds", Target: "api.stripe.com"},
			wantVerdict: recorder.VerdictWouldDeny,
			wantReason:  "not_in_allowlist",
		},
		{
			name: "permitted host on a port the policy does not allow",
			obs: recorder.Observation{AgentID: "support-agent",
				Resource: "http://api.zendesk.com/tickets", Target: "api.zendesk.com"},
			wantVerdict: recorder.VerdictWouldDeny,
			wantReason:  "not_in_allowlist",
		},
		{
			name: "cloud metadata endpoint",
			obs: recorder.Observation{AgentID: "support-agent",
				Resource: "http://169.254.169.254/latest/meta-data/", Target: "169.254.169.254"},
			wantVerdict: recorder.VerdictWouldDeny,
			wantReason:  "metadata_endpoint",
		},
		{
			name: "internal address",
			obs: recorder.Observation{AgentID: "support-agent",
				Resource: "http://10.0.0.5:8080/admin", Target: "10.0.0.5:8080"},
			wantVerdict: recorder.VerdictWouldDeny,
			wantReason:  "private_address_denied",
		},
		{
			name: "an agent the policy does not name",
			obs: recorder.Observation{AgentID: "some-other-agent",
				Resource: "https://api.zendesk.com/x", Target: "api.zendesk.com"},
			wantVerdict: recorder.VerdictWouldDeny,
		},
		{
			name:        "no destination at all",
			obs:         recorder.Observation{AgentID: "support-agent", Action: "gen_ai.chat"},
			wantVerdict: recorder.VerdictNotEvaluable,
			wantReason:  "no_destination",
		},
		{
			name: "host known, port unknown, host is allowed",
			obs: recorder.Observation{AgentID: "support-agent",
				Target: "api.zendesk.com"},
			wantVerdict: recorder.VerdictNotEvaluable,
			wantReason:  "destination_port_unknown",
		},
		{
			name: "host known, port unknown, host is not allowed anywhere",
			obs: recorder.Observation{AgentID: "support-agent",
				Target: "api.stripe.com"},
			wantVerdict: recorder.VerdictWouldDeny,
			wantReason:  "not_in_allowlist",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			verdict, reason := e.Evaluate(tc.obs)
			if verdict != tc.wantVerdict {
				t.Errorf("verdict = %q, want %q (reason %q)", verdict, tc.wantVerdict, reason)
			}
			if tc.wantReason != "" && reason != tc.wantReason {
				t.Errorf("reason = %q, want %q", reason, tc.wantReason)
			}
		})
	}
}

// TestUnknownPortDoesNotBecomeAnAllow is the honesty property of shadow mode.
//
// An operator turns enforcement on based on what shadow mode told them. A
// guessed port that happened to match would produce a confident "would allow"
// for a destination enforcement might refuse, and the surprise arrives in
// production.
func TestUnknownPortDoesNotBecomeAnAllow(t *testing.T) {
	e := evaluator(t)

	verdict, reason := e.Evaluate(recorder.Observation{
		AgentID: "support-agent",
		Target:  "api.zendesk.com", // allowed host, but on which port?
	})
	if verdict == recorder.VerdictWouldAllow {
		t.Errorf("an unknown port was reported as allowed (reason %q)", reason)
	}
}

// TestShadowSummaryReportsCoverage: the not-evaluable count is how much of the
// agent's behaviour the policy does not speak to, and hiding it would make a
// narrow policy look complete.
func TestShadowSummaryReportsCoverage(t *testing.T) {
	c := recorder.ShadowCounts{WouldAllow: 10, WouldDeny: 3, NotEvaluable: 7}
	s := c.Summary()
	for _, want := range []string{"20 observed", "10 would be allowed", "3 would be DENIED", "7 not covered"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q is missing %q", s, want)
		}
	}
}

// TestModelProviderIsNotADestination guards against a false positive that
// would cost shadow mode its credibility.
//
// gen_ai.system carries a provider name, not a hostname. Treating it as a
// destination made an ordinary model call come back as
// "would_deny/not_in_allowlist" -- and an operator who finds one bogus denial
// in a report stops trusting the other three.
func TestModelProviderIsNotADestination(t *testing.T) {
	e := evaluator(t)

	verdict, reason := e.Evaluate(recorder.Observation{
		AgentID:  "support-agent",
		Action:   "gen_ai.chat",
		Resource: "claude-opus-5",
		Provider: "anthropic",
	})

	if verdict == recorder.VerdictWouldDeny {
		t.Errorf("a model call was reported as a policy denial (reason %q); "+
			"the provider name is not a network destination", reason)
	}
	if verdict != recorder.VerdictNotEvaluable {
		t.Errorf("verdict = %q, want %q", verdict, recorder.VerdictNotEvaluable)
	}
}

// TestShadowNamesAnUnknownAgent pins what a real user test found: an agent
// reporting itself as "python-agent" against a policy for "my-agent" had
// every request reported as not_in_allowlist, even for hosts the policy
// allows, which sends the operator looking for a missing host rather than a
// name that does not match.
func TestShadowNamesAnUnknownAgent(t *testing.T) {
	e := evaluator(t)

	v, r := e.Evaluate(recorder.Observation{AgentID: "python-agent",
		Resource: "https://api.zendesk.com/tickets/42", Target: "api.zendesk.com"})
	if v != recorder.VerdictWouldDeny || r != "unknown_workload" {
		t.Errorf("unknown agent, allowed host: got %s/%s, want would_deny/unknown_workload", v, r)
	}
	// Structural refusals are still reported as what they are.
	v, r = e.Evaluate(recorder.Observation{AgentID: "python-agent",
		Resource: "http://169.254.169.254/latest/meta-data/"})
	if v != recorder.VerdictWouldDeny || r != "metadata_endpoint" {
		t.Errorf("unknown agent, metadata endpoint: got %s/%s, want would_deny/metadata_endpoint", v, r)
	}
	// A known agent is unaffected.
	if v, _ := e.Evaluate(recorder.Observation{AgentID: "support-agent",
		Resource: "https://api.zendesk.com/x"}); v != recorder.VerdictWouldAllow {
		t.Errorf("known agent, allowed host: got %s", v)
	}
	if got := e.UnknownAgents(); len(got) != 1 || got[0] != "python-agent" {
		t.Errorf("UnknownAgents() = %v, want [python-agent]", got)
	}
}
