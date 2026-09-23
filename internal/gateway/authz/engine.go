package authz

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/Aryan22g/agw/internal/gateway/decision"
)

// Engine evaluates authorization requests.
//
// The gateway depends on this interface, not on a concrete engine, so the
// native evaluator and an external OPA deployment are interchangeable without
// touching the request pipeline.
type Engine interface {
	// Authorize returns an allow decision, or a deny/error decision that
	// the caller must honour. It never returns a bare error alongside an
	// allow.
	Authorize(ctx context.Context, req Request) decision.Decision
}

// NativeEngine evaluates the built-in YAML policy language.
//
// It holds policies in memory and evaluates without I/O, so authorization
// adds no network dependency to the request path. That is the main reason it
// is the default: an external policy server is one more thing that can be
// down, and a fail-closed gateway turns that outage into a full outage.
type NativeEngine struct {
	mu       sync.RWMutex
	policies map[string]*Policy
}

// NewNativeEngine builds an engine over a set of tenant policies.
func NewNativeEngine(policies map[string]*Policy) (*NativeEngine, error) {
	if policies == nil {
		policies = map[string]*Policy{}
	}
	for tenant, p := range policies {
		if p == nil {
			return nil, fmt.Errorf("nil policy for tenant %q", tenant)
		}
		if err := p.Validate(); err != nil {
			return nil, err
		}
	}
	return &NativeEngine{policies: policies}, nil
}

// NewNativeEngineFromDir loads policies from a directory.
func NewNativeEngineFromDir(dir string) (*NativeEngine, error) {
	policies, err := LoadPolicyDir(dir)
	if err != nil {
		return nil, err
	}
	return NewNativeEngine(policies)
}

// Replace swaps the policy set atomically, for hot reload.
func (e *NativeEngine) Replace(policies map[string]*Policy) error {
	for tenant, p := range policies {
		if p == nil {
			return fmt.Errorf("nil policy for tenant %q", tenant)
		}
		if err := p.Validate(); err != nil {
			return err
		}
	}

	e.mu.Lock()
	e.policies = policies
	e.mu.Unlock()
	return nil
}

// Authorize evaluates a request against the tenant's policy.
//
// Evaluation order is deny-overrides:
//
//  1. no policy for the tenant -> deny. A tenant with no policy has granted
//     nothing; defaulting to allow would mean onboarding a tenant silently
//     opens every route to it.
//  2. any matching deny rule -> deny, regardless of matching allows. This
//     makes a deny rule a genuine guarantee rather than something an
//     later-added allow can quietly override.
//  3. any matching allow rule -> allow.
//  4. otherwise -> deny. Default deny.
func (e *NativeEngine) Authorize(_ context.Context, req Request) decision.Decision {
	if req.Now.IsZero() {
		req.Now = time.Now().UTC()
	}

	e.mu.RLock()
	policy, ok := e.policies[req.TenantID]
	e.mu.RUnlock()

	if !ok || policy == nil {
		return decision.Deny(decision.ReasonNoPolicyForAgent, nil,
			fmt.Sprintf("no policy configured for tenant %q", req.TenantID))
	}

	var matchedAllow string

	for i := range policy.Rules {
		rule := &policy.Rules[i]
		if !rule.Matches(req) {
			continue
		}

		if rule.Effect == EffectDeny {
			return decision.Deny(decision.ReasonPolicyDenied, nil,
				fmt.Sprintf("rule %q denies %s on %s for agent %s",
					rule.ID, req.Action, req.Resource, req.AgentID))
		}
		if matchedAllow == "" {
			matchedAllow = rule.ID
		}
	}

	if matchedAllow != "" {
		return decision.Allow()
	}

	return decision.Deny(decision.ReasonPolicyDenied, nil,
		fmt.Sprintf("no rule allows %s on %s for agent %s in tenant %s",
			req.Action, req.Resource, req.AgentID, req.TenantID))
}
