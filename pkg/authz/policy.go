// Package authz is the Stage-3 authorization plane.
//
// It answers one question: may this already-authenticated principal perform
// this action on this resource? Authentication is a separate, earlier decision
// -- "who is this?" and "may they?" have different failure modes, different
// audit meanings and different HTTP statuses, so they are kept apart.
package authz

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Aryan22g/agw/pkg/routing"
)

// Effect is a rule's verdict.
type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Policy is one tenant's authorization policy.
type Policy struct {
	Tenant  string `yaml:"tenant"`
	Version string `yaml:"version"`

	// Rules are evaluated in order, but an explicit deny anywhere in the
	// set wins over any allow. See Evaluate.
	Rules []Rule `yaml:"rules"`
}

// Rule grants or refuses a set of actions to a set of agents.
type Rule struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description,omitempty"`

	Effect Effect `yaml:"effect"`

	// Agents matches agent ids. "*" matches any agent in the tenant.
	Agents []string `yaml:"agents"`

	// Actions matches route actions, e.g. "github.issue.create".
	// A trailing ".*" matches a prefix, e.g. "github.issue.*".
	Actions []string `yaml:"actions"`

	// Resources matches resource ids, e.g. "acme/app". "*" matches any.
	// A trailing "/*" matches a prefix.
	Resources []string `yaml:"resources,omitempty"`

	// MaxRiskClass caps the risk of routes this rule may authorize.
	// Empty means no cap beyond what Actions already implies.
	MaxRiskClass routing.RiskClass `yaml:"max_risk_class,omitempty"`

	// NotBefore and NotAfter bound when the rule is live, for
	// time-limited delegation.
	NotBefore *time.Time `yaml:"not_before,omitempty"`
	NotAfter  *time.Time `yaml:"not_after,omitempty"`
}

// Request is the input to an authorization decision.
type Request struct {
	TenantID  string
	AgentID   string
	Action    string
	Resource  string
	RiskClass routing.RiskClass
	Now       time.Time

	// Federated marks a principal from another organization. It changes how
	// agent wildcards are read: see Rule.Matches.
	Federated bool
}

// riskOrder ranks risk classes so MaxRiskClass can be compared.
var riskOrder = map[routing.RiskClass]int{
	routing.RiskRead:        0,
	routing.RiskWrite:       1,
	routing.RiskPrivileged:  2,
	routing.RiskDestructive: 3,
}

// Validate checks a policy is well formed.
//
// Policies are operator input that gates every request, so a malformed one
// must fail at load time. Failing later, per-request, would mean a typo in a
// rule surfaces as production traffic being denied -- or worse, as a rule
// silently never matching.
func (p *Policy) Validate() error {
	if strings.TrimSpace(p.Tenant) == "" {
		return fmt.Errorf("policy: tenant is required")
	}
	if len(p.Rules) == 0 {
		return fmt.Errorf("policy %q: at least one rule is required", p.Tenant)
	}

	seen := make(map[string]struct{}, len(p.Rules))
	for i := range p.Rules {
		r := &p.Rules[i]

		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("policy %q: rule %d has no id", p.Tenant, i)
		}
		if _, dup := seen[r.ID]; dup {
			return fmt.Errorf("policy %q: duplicate rule id %q", p.Tenant, r.ID)
		}
		seen[r.ID] = struct{}{}

		switch r.Effect {
		case EffectAllow, EffectDeny:
		case "":
			return fmt.Errorf("policy %q rule %q: effect is required (allow or deny)", p.Tenant, r.ID)
		default:
			return fmt.Errorf("policy %q rule %q: unknown effect %q", p.Tenant, r.ID, r.Effect)
		}

		if len(r.Agents) == 0 {
			return fmt.Errorf("policy %q rule %q: at least one agent is required", p.Tenant, r.ID)
		}
		if len(r.Actions) == 0 {
			return fmt.Errorf("policy %q rule %q: at least one action is required", p.Tenant, r.ID)
		}
		for _, a := range r.Actions {
			if err := validateActionPattern(a); err != nil {
				return fmt.Errorf("policy %q rule %q: %w", p.Tenant, r.ID, err)
			}
		}
		for _, res := range r.Resources {
			if err := validateResourcePattern(res); err != nil {
				return fmt.Errorf("policy %q rule %q: %w", p.Tenant, r.ID, err)
			}
		}

		if r.MaxRiskClass != "" {
			if _, ok := riskOrder[r.MaxRiskClass]; !ok {
				return fmt.Errorf("policy %q rule %q: unknown max_risk_class %q",
					p.Tenant, r.ID, r.MaxRiskClass)
			}
		}

		if r.NotBefore != nil && r.NotAfter != nil && r.NotAfter.Before(*r.NotBefore) {
			return fmt.Errorf("policy %q rule %q: not_after precedes not_before", p.Tenant, r.ID)
		}
	}

	return nil
}

// Matches reports whether a rule applies to a request.
func (r *Rule) Matches(req Request) bool {
	if !r.live(req.Now) {
		return false
	}
	if !r.matchesAgent(req) {
		return false
	}
	if !matchAny(r.Actions, req.Action, matchActionPattern) {
		return false
	}
	// An empty Resources list means the rule is not resource-scoped.
	if len(r.Resources) > 0 && !matchAny(r.Resources, req.Resource, matchResourcePattern) {
		return false
	}
	if r.MaxRiskClass != "" {
		allowed, ok := riskOrder[r.MaxRiskClass]
		actual, ok2 := riskOrder[req.RiskClass]
		if !ok || !ok2 || actual > allowed {
			return false
		}
	}
	return true
}

// matchesAgent decides whether a rule's agent list covers the caller.
//
// A bare "*" means "any agent of THIS tenant", never "any agent anywhere". A
// federated principal must be named explicitly, or by the federated: form
// below. Without this distinction, shipping federation would silently turn
// every existing `agents: ["*"]` policy into an open door for any partner the
// operator later configures -- a change in meaning nobody asked for and
// nobody would see in a diff.
func (r *Rule) matchesAgent(req Request) bool {
	for _, pattern := range r.Agents {
		if strings.HasPrefix(pattern, "federated:") {
			if !req.Federated {
				continue
			}
			// "federated:*" admits any trusted issuer's agents;
			// "federated:<agent-id>" names one.
			suffix := strings.TrimPrefix(pattern, "federated:")
			if suffix == "*" || suffix == req.AgentID {
				return true
			}
			continue
		}

		if req.Federated {
			// Plain patterns, including "*", apply to local agents only.
			continue
		}
		if matchExactOrStar(pattern, req.AgentID) {
			return true
		}
	}
	return false
}

func (r *Rule) live(now time.Time) bool {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if r.NotBefore != nil && now.Before(*r.NotBefore) {
		return false
	}
	if r.NotAfter != nil && now.After(*r.NotAfter) {
		return false
	}
	return true
}

func matchAny(patterns []string, value string, match func(pattern, value string) bool) bool {
	for _, p := range patterns {
		if match(p, value) {
			return true
		}
	}
	return false
}

func matchExactOrStar(pattern, value string) bool {
	return pattern == "*" || pattern == value
}

// matchActionPattern supports exact match and a trailing ".*" prefix wildcard,
// e.g. "github.issue.*" matches "github.issue.create".
//
// The wildcard must follow a dot so that "github.issue.*" cannot also match
// "github.issueDelete" -- wildcards that ignore the separator are a common
// source of policies that grant more than their author intended.
// validateActionPattern rejects a wildcard in a position the matcher does not
// support.
//
// Without this, "github.issue*" or "mcp.tool.search_*" loads cleanly and then
// matches nothing, for ever. On an allow rule that is a confusing outage; on a
// DENY rule it is a guardrail an operator believes they have and does not --
// which is the failure mode worth being loud about.
func validateActionPattern(pattern string) error {
	if pattern == "*" || !strings.Contains(pattern, "*") {
		return nil
	}
	if strings.HasSuffix(pattern, ".*") && strings.Count(pattern, "*") == 1 {
		return nil
	}
	return fmt.Errorf(
		"action pattern %q: a wildcard is only supported alone (\"*\") or as a trailing \".*\" "+
			"on the dot boundary; %q would never match anything", pattern, pattern)
}

// validateResourcePattern is the same check for resources, whose wildcard is
// a trailing "/*".
func validateResourcePattern(pattern string) error {
	if pattern == "*" || !strings.Contains(pattern, "*") {
		return nil
	}
	if strings.HasSuffix(pattern, "/*") && strings.Count(pattern, "*") == 1 {
		return nil
	}
	return fmt.Errorf(
		"resource pattern %q: a wildcard is only supported alone (\"*\") or as a trailing \"/*\"; "+
			"%q would never match anything", pattern, pattern)
}

func matchActionPattern(pattern, value string) bool {
	if pattern == "*" || pattern == value {
		return true
	}
	if strings.HasSuffix(pattern, ".*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	return false
}

// matchResourcePattern supports exact match and a trailing "/*" prefix
// wildcard, e.g. "acme/*" matches "acme/app".
func matchResourcePattern(pattern, value string) bool {
	if pattern == "*" || pattern == value {
		return true
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	return false
}

// LoadPolicyFile reads and validates one policy document.
func LoadPolicyFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}

	var p Policy
	// KnownFields makes an unrecognised key an error rather than a silent
	// no-op. A misspelled "resource:" that parses to nothing would
	// otherwise widen a rule from one resource to all of them.
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy %s: %w", path, err)
	}

	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy %s: %w", path, err)
	}
	return &p, nil
}

// LoadPolicyDir loads every .yaml/.yml policy in a directory, keyed by tenant.
func LoadPolicyDir(dir string) (map[string]*Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read policy dir %s: %w", dir, err)
	}

	out := make(map[string]*Policy)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}

		p, err := LoadPolicyFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if _, dup := out[p.Tenant]; dup {
			return nil, fmt.Errorf("duplicate policy for tenant %q in %s", p.Tenant, dir)
		}
		out[p.Tenant] = p
	}

	return out, nil
}
