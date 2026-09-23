package authz_test

import (
	"context"
	"testing"
	"time"

	"github.com/Aryan22g/agw/internal/gateway/authz"
	"github.com/Aryan22g/agw/internal/gateway/decision"
	"github.com/Aryan22g/agw/internal/gateway/routing"
)

func engine(t *testing.T, p *authz.Policy) *authz.NativeEngine {
	t.Helper()
	e, err := authz.NewNativeEngine(map[string]*authz.Policy{p.Tenant: p})
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return e
}

func basePolicy() *authz.Policy {
	return &authz.Policy{
		Tenant:  "tenant-alpha",
		Version: "1",
		Rules: []authz.Rule{
			{
				ID:        "support-reads",
				Effect:    authz.EffectAllow,
				Agents:    []string{"agent-support"},
				Actions:   []string{"github.issue.*"},
				Resources: []string{"acme/*"},
			},
			{
				ID:           "billing-writes-capped",
				Effect:       authz.EffectAllow,
				Agents:       []string{"agent-billing"},
				Actions:      []string{"billing.refund.create"},
				Resources:    []string{"*"},
				MaxRiskClass: routing.RiskWrite,
			},
			{
				ID:      "never-delete",
				Effect:  authz.EffectDeny,
				Agents:  []string{"*"},
				Actions: []string{"github.repo.delete"},
			},
		},
	}
}

func req(agent, action, resource string, risk routing.RiskClass) authz.Request {
	return authz.Request{
		TenantID:  "tenant-alpha",
		AgentID:   agent,
		Action:    action,
		Resource:  resource,
		RiskClass: risk,
		Now:       time.Now().UTC(),
	}
}

func TestAllowsMatchingRule(t *testing.T) {
	e := engine(t, basePolicy())

	d := e.Authorize(context.Background(),
		req("agent-support", "github.issue.create", "acme/app", routing.RiskWrite))

	if !d.Allowed() {
		t.Fatalf("expected allow, got %s: %s", d.Reason, d.Detail)
	}
}

// TestDefaultDeny is the property that makes the whole layer trustworthy:
// anything not explicitly granted is refused.
func TestDefaultDeny(t *testing.T) {
	e := engine(t, basePolicy())

	cases := []struct {
		name string
		req  authz.Request
	}{
		{"unknown action", req("agent-support", "billing.refund.create", "acme/app", routing.RiskWrite)},
		{"unknown agent", req("agent-rogue", "github.issue.create", "acme/app", routing.RiskWrite)},
		{"out of scope resource", req("agent-support", "github.issue.create", "other/app", routing.RiskWrite)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := e.Authorize(context.Background(), tc.req)
			if d.Allowed() {
				t.Fatal("expected deny, got allow")
			}
			if d.Reason != decision.ReasonPolicyDenied {
				t.Errorf("reason = %s, want %s", d.Reason, decision.ReasonPolicyDenied)
			}
			if d.HTTPStatus() != 403 {
				t.Errorf("status = %d, want 403", d.HTTPStatus())
			}
		})
	}
}

// TestDenyOverridesAllow guards the ordering guarantee: an explicit deny must
// not be defeatable by adding a broader allow.
func TestDenyOverridesAllow(t *testing.T) {
	p := basePolicy()
	p.Rules = append(p.Rules, authz.Rule{
		ID:        "support-everything",
		Effect:    authz.EffectAllow,
		Agents:    []string{"agent-support"},
		Actions:   []string{"*"},
		Resources: []string{"*"},
	})

	e := engine(t, p)
	d := e.Authorize(context.Background(),
		req("agent-support", "github.repo.delete", "acme/app", routing.RiskDestructive))

	if d.Allowed() {
		t.Fatal("a blanket allow overrode an explicit deny")
	}
}

// TestRiskClassCap covers the delegation-limit story: an agent allowed to do
// an action must still not exceed its permitted risk class.
func TestRiskClassCap(t *testing.T) {
	e := engine(t, basePolicy())

	if d := e.Authorize(context.Background(),
		req("agent-billing", "billing.refund.create", "any", routing.RiskWrite)); !d.Allowed() {
		t.Fatalf("write within cap was denied: %s", d.Detail)
	}

	if d := e.Authorize(context.Background(),
		req("agent-billing", "billing.refund.create", "any", routing.RiskDestructive)); d.Allowed() {
		t.Fatal("a destructive action exceeded max_risk_class=write and was allowed")
	}
}

// TestTenantWithoutPolicyDenied: onboarding a tenant must not implicitly open
// every route to it.
func TestTenantWithoutPolicyDenied(t *testing.T) {
	e := engine(t, basePolicy())

	d := e.Authorize(context.Background(), authz.Request{
		TenantID: "tenant-unknown",
		AgentID:  "agent-support",
		Action:   "github.issue.create",
		Resource: "acme/app",
		Now:      time.Now().UTC(),
	})

	if d.Allowed() {
		t.Fatal("a tenant with no policy was allowed")
	}
	if d.Reason != decision.ReasonNoPolicyForAgent {
		t.Errorf("reason = %s, want %s", d.Reason, decision.ReasonNoPolicyForAgent)
	}
}

// TestTimeBoundedDelegation covers expiring grants.
func TestTimeBoundedDelegation(t *testing.T) {
	past := time.Now().UTC().Add(-2 * time.Hour)
	expired := time.Now().UTC().Add(-time.Hour)

	p := &authz.Policy{
		Tenant: "tenant-alpha",
		Rules: []authz.Rule{{
			ID:        "temporary",
			Effect:    authz.EffectAllow,
			Agents:    []string{"agent-temp"},
			Actions:   []string{"github.issue.create"},
			NotBefore: &past,
			NotAfter:  &expired,
		}},
	}

	e := engine(t, p)
	d := e.Authorize(context.Background(),
		req("agent-temp", "github.issue.create", "acme/app", routing.RiskWrite))

	if d.Allowed() {
		t.Fatal("an expired delegation was still honoured")
	}
}

// TestActionWildcardRespectsSeparator: "github.issue.*" must not match
// "github.issueDelete".
func TestActionWildcardRespectsSeparator(t *testing.T) {
	e := engine(t, basePolicy())

	d := e.Authorize(context.Background(),
		req("agent-support", "github.issueDelete", "acme/app", routing.RiskDestructive))

	if d.Allowed() {
		t.Fatal("wildcard github.issue.* matched github.issueDelete")
	}
}

func TestInvalidPolicyRejectedAtLoad(t *testing.T) {
	cases := map[string]*authz.Policy{
		"no tenant":      {Rules: []authz.Rule{{ID: "r", Effect: authz.EffectAllow, Agents: []string{"*"}, Actions: []string{"*"}}}},
		"no rules":       {Tenant: "t"},
		"unknown effect": {Tenant: "t", Rules: []authz.Rule{{ID: "r", Effect: "maybe", Agents: []string{"*"}, Actions: []string{"*"}}}},
		"no rule id":     {Tenant: "t", Rules: []authz.Rule{{Effect: authz.EffectAllow, Agents: []string{"*"}, Actions: []string{"*"}}}},
		"bad risk":       {Tenant: "t", Rules: []authz.Rule{{ID: "r", Effect: authz.EffectAllow, Agents: []string{"*"}, Actions: []string{"*"}, MaxRiskClass: "catastrophic"}}},
	}

	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			if err := p.Validate(); err == nil {
				t.Error("invalid policy passed validation")
			}
		})
	}
}
