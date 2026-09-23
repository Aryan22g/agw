package agentgw

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Error is a structured gateway denial.
//
// Callers should branch on Reason rather than on Status: the reason code is a
// stable contract, while several distinct reasons deliberately share a status
// so the gateway does not reveal which of them applied.
type Error struct {
	Status     int    `json:"status"`
	Reason     string `json:"reason"`
	Title      string `json:"title"`
	DecisionID string `json:"decisionId"`
	Type       string `json:"type"`
}

func (e *Error) Error() string {
	if e.DecisionID != "" {
		return fmt.Sprintf("agentgw: gateway returned %d %s (decision %s)",
			e.Status, e.Reason, e.DecisionID)
	}
	return fmt.Sprintf("agentgw: gateway returned %d %s", e.Status, e.Reason)
}

// Reason codes the gateway can return. These mirror
// internal/gateway/decision.
const (
	ReasonSignatureInvalid   = "signature_invalid"
	ReasonSignatureMalformed = "signature_malformed"
	ReasonDigestMismatch     = "digest_mismatch"
	ReasonRequestExpired     = "request_expired"
	ReasonPrincipalNotFound  = "principal_not_found"
	ReasonCredentialRevoked  = "credential_revoked"
	ReasonCredentialExpired  = "credential_expired"
	ReasonReplayDetected     = "replay_detected"
	ReasonPolicyDenied       = "policy_denied"
	ReasonRateLimited        = "rate_limited"
	ReasonRouteUnknown       = "route_unknown"
)

// Retryable reports whether retrying the same logical call could succeed.
//
// A replayed nonce is retryable because the SDK mints a fresh nonce per
// attempt, so a retry is a genuinely new request. A policy denial is not:
// retrying it just produces the same denial and burns rate-limit budget.
func (e *Error) Retryable() bool {
	switch e.Reason {
	case ReasonReplayDetected, ReasonRateLimited:
		return true
	default:
		return e.Status >= 500
	}
}

// IsRevoked reports whether the failure means this credential is finished and
// the agent should re-register rather than retry.
func (e *Error) IsRevoked() bool {
	return e.Reason == ReasonCredentialRevoked || e.Reason == ReasonCredentialExpired
}

func parseError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))

	out := &Error{Status: resp.StatusCode}
	if err := json.Unmarshal(body, out); err != nil || out.Reason == "" {
		// A non-JSON error body means something other than the gateway
		// answered -- a proxy or load balancer, say. Surface the status
		// rather than inventing a reason code.
		out.Reason = "unknown"
		out.Title = http.StatusText(resp.StatusCode)
	}
	out.Status = resp.StatusCode
	return out
}
