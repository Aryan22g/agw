// Package decision defines the gateway's typed allow/deny outcome.
//
// Every terminal point in the request pipeline produces a Decision. This
// replaces mapping errors to HTTP statuses by substring-matching their
// messages, which was both fragile and unsafe: an infrastructure error whose
// text happened to contain "policy" would surface to the caller as a 403
// authorization denial, and a change to an unrelated error string could
// silently change the gateway's HTTP behaviour.
package decision

import "net/http"

// Outcome is the coarse result of the pipeline.
type Outcome string

const (
	OutcomeAllow Outcome = "allow"
	OutcomeDeny  Outcome = "deny"
	OutcomeError Outcome = "error"
)

// Reason is a stable, machine-readable denial code.
//
// These strings are a public contract: they appear in audit events, in
// metrics labels, and in the gateway's JSON error body, so callers and SIEM
// rules can depend on them. Add new values rather than repurposing existing
// ones.
type Reason string

const (
	ReasonAllowed Reason = "allowed"

	// Request shape.
	ReasonBodyTooLarge     Reason = "body_too_large"
	ReasonMalformedRequest Reason = "malformed_request"
	ReasonMissingHeaders   Reason = "missing_required_headers"
	ReasonRouteUnknown     Reason = "route_unknown"

	// Authentication (Stage-1 + Stage-2).
	ReasonSignatureMalformed Reason = "signature_malformed"
	ReasonSignatureInvalid   Reason = "signature_invalid"
	ReasonDigestMismatch     Reason = "digest_mismatch"
	ReasonRequestExpired     Reason = "request_expired"
	ReasonRequestNotYetValid Reason = "request_not_yet_valid"
	ReasonPrincipalNotFound  Reason = "principal_not_found"
	ReasonCredentialRevoked  Reason = "credential_revoked"
	ReasonCredentialExpired  Reason = "credential_expired"
	ReasonPrincipalInactive  Reason = "principal_inactive"
	ReasonTenantMismatch     Reason = "tenant_mismatch"
	ReasonReplayDetected     Reason = "replay_detected"

	// Federation (Stage-5).
	ReasonNoTrustRelationship Reason = "no_trust_relationship"
	ReasonTrustNotActive      Reason = "trust_not_active"
	ReasonTrustExpired        Reason = "trust_expired"
	ReasonOutsideTrustGrant   Reason = "outside_trust_grant"
	ReasonIssuerUnavailable   Reason = "issuer_unavailable"
	ReasonKeyNotPublished     Reason = "key_not_published"

	// Authorization (Stage-3).
	ReasonPolicyDenied     Reason = "policy_denied"
	ReasonNoPolicyForAgent Reason = "no_policy_for_agent"
	ReasonRateLimited      Reason = "rate_limited"

	// Infrastructure. These are deliberately distinct from denials: a
	// dependency being down is not the same event as an agent being refused,
	// and conflating them makes both alerting and incident response worse.
	ReasonDependencyUnavailable Reason = "dependency_unavailable"
	ReasonBackendUnavailable    Reason = "backend_unavailable"
	ReasonInternalError         Reason = "internal_error"
)

// Decision is the outcome of evaluating one request.
type Decision struct {
	Outcome Outcome
	Reason  Reason

	// Detail is operator-facing context. It is logged and audited but never
	// returned to the caller, because it can carry internal identifiers and
	// dependency error text.
	Detail string

	// Err is the underlying cause, for logging.
	Err error
}

// Allow returns an allow decision.
func Allow() Decision {
	return Decision{Outcome: OutcomeAllow, Reason: ReasonAllowed}
}

// Deny returns a deny decision: the request was understood and refused.
func Deny(reason Reason, err error, detail string) Decision {
	return Decision{Outcome: OutcomeDeny, Reason: reason, Detail: detail, Err: err}
}

// Fail returns an error decision: the gateway could not reach a verdict.
//
// This is still a rejection. AGS1 fails closed, so an inability to decide is
// never an allow -- it only changes which status and which alert fire.
func Fail(reason Reason, err error, detail string) Decision {
	return Decision{Outcome: OutcomeError, Reason: reason, Detail: detail, Err: err}
}

// Allowed reports whether the request may proceed.
func (d Decision) Allowed() bool {
	return d.Outcome == OutcomeAllow
}

// HTTPStatus maps a decision to its response status.
//
// The mapping is intentionally coarse toward the caller. An unauthenticated
// caller learns only that it failed, not which of credential lookup, signature
// check or revocation rejected it -- distinguishing those would turn the
// gateway into an oracle for probing which tenants, agents and keys exist.
func (d Decision) HTTPStatus() int {
	switch d.Reason {
	case ReasonAllowed:
		return http.StatusOK

	case ReasonBodyTooLarge:
		return http.StatusRequestEntityTooLarge

	case ReasonRouteUnknown:
		return http.StatusNotFound

	case ReasonMalformedRequest,
		ReasonMissingHeaders,
		ReasonSignatureMalformed:
		return http.StatusBadRequest

	case ReasonSignatureInvalid,
		ReasonDigestMismatch,
		ReasonRequestExpired,
		ReasonRequestNotYetValid,
		ReasonPrincipalNotFound,
		ReasonCredentialRevoked,
		ReasonCredentialExpired,
		ReasonPrincipalInactive,
		ReasonTenantMismatch,
		// An unknown issuer is reported as an authentication failure rather
		// than a distinct status: telling an unauthenticated caller whether
		// an issuer is merely unconfigured versus suspended would let them
		// enumerate this deployment's partnerships.
		ReasonNoTrustRelationship,
		ReasonTrustNotActive,
		ReasonTrustExpired,
		ReasonKeyNotPublished:
		return http.StatusUnauthorized

	case ReasonReplayDetected:
		return http.StatusConflict

	case ReasonPolicyDenied,
		ReasonNoPolicyForAgent,
		// The caller authenticated as a known partner; they simply are not
		// granted this action. That is a 403, the same as a local denial.
		ReasonOutsideTrustGrant:
		return http.StatusForbidden

	case ReasonRateLimited:
		return http.StatusTooManyRequests

	case ReasonBackendUnavailable:
		return http.StatusBadGateway

	case ReasonDependencyUnavailable,
		ReasonIssuerUnavailable:
		return http.StatusServiceUnavailable

	default:
		// Unknown reasons fail closed as a server error rather than
		// falling through to a success status.
		return http.StatusInternalServerError
	}
}

// PublicMessage is the caller-facing text for a decision.
//
// Deliberately generic per status class. Detail stays server-side.
func (d Decision) PublicMessage() string {
	switch d.HTTPStatus() {
	case http.StatusRequestEntityTooLarge:
		return "request body too large"
	case http.StatusNotFound:
		return "no route matches this request"
	case http.StatusBadRequest:
		return "malformed request"
	case http.StatusUnauthorized:
		return "request could not be authenticated"
	case http.StatusConflict:
		return "request has already been seen"
	case http.StatusForbidden:
		return "request is not authorized"
	case http.StatusTooManyRequests:
		return "rate limit exceeded"
	case http.StatusBadGateway:
		return "upstream service unavailable"
	case http.StatusServiceUnavailable:
		return "service temporarily unavailable"
	default:
		return "internal error"
	}
}
