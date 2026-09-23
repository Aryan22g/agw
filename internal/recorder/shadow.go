package recorder

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"github.com/Aryan22g/agw/internal/confine"
)

// Shadow verdicts.
//
// The third one carries the weight. A policy that cannot speak to an
// observation must say so rather than pass it, because shadow mode exists to
// tell an operator what enforcement would do -- and a silent "would allow"
// over something the policy never considered is exactly the false comfort
// that makes people turn enforcement on and get surprised.
const (
	VerdictWouldAllow   = "would_allow"
	VerdictWouldDeny    = "would_deny"
	VerdictNotEvaluable = "not_evaluable"
)

// Evaluator answers what egress policy would have done about an observation.
type Evaluator struct {
	policy *confine.Policy
	guard  *confine.Guard
}

// NewEvaluator builds an Evaluator from an egress policy.
func NewEvaluator(policy *confine.Policy) (*Evaluator, error) {
	if policy == nil {
		return nil, errors.New("recorder: a policy is required")
	}
	guard, err := confine.NewGuard(policy.PermitPrivate)
	if err != nil {
		return nil, err
	}
	return &Evaluator{policy: policy, guard: guard}, nil
}

// Evaluate returns a verdict and a reason for one observation.
func (e *Evaluator) Evaluate(obs Observation) (verdict, reason string) {
	host, port, known := destinationOf(obs)
	if host == "" {
		return VerdictNotEvaluable, "no_destination"
	}

	// Structural denials first, so a probe at a metadata endpoint is reported
	// as what it is rather than as an ordinary allowlist miss. Same ordering,
	// and the same reasoning, as the enforcement path in confine.
	if literal, err := netip.ParseAddr(host); err == nil {
		if err := e.guard.Check(literal); err != nil {
			return VerdictWouldDeny, confine.Reason(err)
		}
	}

	if !known {
		// The host is known but the port is not. A host no rule names is a
		// definitive deny regardless of port; a host some rule names cannot
		// be confirmed without one.
		if !e.policy.PermitsHost(obs.AgentID, host) {
			return VerdictWouldDeny, "not_in_allowlist"
		}
		return VerdictNotEvaluable, "destination_port_unknown"
	}

	if _, err := e.policy.Permits(obs.AgentID, host, port); err != nil {
		return VerdictWouldDeny, confine.Reason(confine.ErrNotPermitted)
	}
	return VerdictWouldAllow, "permitted"
}

// destinationOf extracts the destination an observation touched.
//
// known reports whether the port is certain. A guessed port would turn an
// uncertain verdict into a confident wrong one.
func destinationOf(obs Observation) (host string, port int, known bool) {
	// A full URL is the best case: scheme fixes the port when it is implicit.
	if raw := strings.TrimSpace(obs.Resource); raw != "" && strings.Contains(raw, "://") {
		if u, err := url.Parse(raw); err == nil && u.Host != "" {
			h := u.Hostname()
			if p := u.Port(); p != "" {
				if n, err := strconv.Atoi(p); err == nil {
					return h, n, true
				}
			}
			switch strings.ToLower(u.Scheme) {
			case "https", "wss":
				return h, 443, true
			case "http", "ws":
				return h, 80, true
			}
			return h, 0, false
		}
	}

	// Otherwise the target attribute, which may carry a port.
	if t := strings.TrimSpace(obs.Target); t != "" {
		if h, p, err := net.SplitHostPort(t); err == nil {
			if n, err := strconv.Atoi(p); err == nil {
				return strings.ToLower(h), n, true
			}
		}
		return strings.ToLower(t), 0, false
	}

	return "", 0, false
}

// ShadowCounts summarises a shadow run.
type ShadowCounts struct {
	WouldAllow   uint64
	WouldDeny    uint64
	NotEvaluable uint64
}

// Summary renders the counts for an operator.
//
// NotEvaluable is reported rather than hidden: it is how much of the agent's
// behaviour this policy does not speak to, which is itself a finding and
// usually the first thing worth acting on.
func (c ShadowCounts) Summary() string {
	total := c.WouldAllow + c.WouldDeny + c.NotEvaluable
	if total == 0 {
		return "no observations to evaluate"
	}
	return fmt.Sprintf(
		"%d observed: %d would be allowed, %d would be DENIED, %d not covered by this policy",
		total, c.WouldAllow, c.WouldDeny, c.NotEvaluable)
}
