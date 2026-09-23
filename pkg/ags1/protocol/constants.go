// Package protocol defines the frozen AGS1 v1 wire constants.
//
// AGS1 is a strict application profile over:
//
//   - RFC 9421 (HTTP Message Signatures)
//   - RFC 9530 (Content-Digest)
//   - RFC 9651 (Structured Field Values)
//   - RFC 7638 (JWK Thumbprint)
//   - RFC 8785 (JSON Canonicalization Scheme)
//   - Ed25519 / EdDSA
//
// Everything in this file is NORMATIVE and frozen for AGS1 v1. Changing any
// value here is a wire-breaking change that requires a new profile version
// (AGS2) and a new tag, never an edit in place. Both the gateway verifier and
// every language SDK derive their behaviour from these constants, so drift
// here is drift everywhere.
//
// Reference: docs/rfcs/RFC-0002-ags1-request-signing-profile.md
package protocol

// Profile identity.
const (
	// ProfileName is the signing profile name.
	ProfileName = "AGS1"

	// SignatureVersion is the value carried in the
	// X-Agent-Signature-Version header and signed as a covered component.
	SignatureVersion = "1"

	// SignatureTag is the RFC 9421 `tag` parameter value. It binds a
	// signature to this profile so a signature minted for another profile
	// cannot be replayed into an AGS1 verifier.
	SignatureTag = "agw-sig-v1"

	// DefaultSignatureLabel is the structured-field label for the signature.
	DefaultSignatureLabel = "sig1"

	// AlgorithmEd25519 is the only algorithm AGS1 v1 permits.
	//
	// The algorithm is deliberately NOT carried on the wire: it is resolved
	// from the registered credential. A client cannot downgrade or influence
	// algorithm selection by editing a header.
	AlgorithmEd25519 = "Ed25519"
)

// Timestamp and replay policy. See RFC-0002 sections 10-12.
const (
	// MaxRequestAgeSeconds is how old a request may be, measured from the
	// signature `created` timestamp.
	MaxRequestAgeSeconds = 300

	// MaxClockSkewSeconds is how far into the future a `created` timestamp
	// may sit before the request is rejected.
	MaxClockSkewSeconds = 60

	// ReplayTTLSeconds is the nonce reservation lifetime.
	//
	// It MUST exceed MaxRequestAgeSeconds + MaxClockSkewSeconds, and by a
	// real margin. Those two bound how long a signed request stays
	// acceptable (300 + 60 = 360s); if a reservation expired at or before
	// that boundary, a captured request could be replayed in the window
	// between its nonce lapsing and the request itself becoming too old.
	//
	// RFC-0002 originally specified 360s, exactly equal to the acceptance
	// window, leaving no margin at all -- and none for clock drift between
	// gateway nodes or for the granularity of Redis key expiry either. 900s
	// gives 9 minutes of headroom on a 6 minute window while keeping
	// reservation storage bounded.
	//
	// This is a server-side storage policy, not a wire value: changing it
	// does not affect signatures and is not a profile-breaking change.
	ReplayTTLSeconds = 900

	// AcceptanceWindowSeconds is how long a signed request stays acceptable.
	// Exposed so the invariant above can be asserted in tests rather than
	// only stated in a comment.
	AcceptanceWindowSeconds = MaxRequestAgeSeconds + MaxClockSkewSeconds

	// NonceMinBytes is the minimum nonce entropy (128 bits).
	NonceMinBytes = 16

	// NonceMinChars / NonceMaxChars bound the encoded nonce length.
	NonceMinChars = 22
	NonceMaxChars = 64
)

// Covered component identifiers. All component identifiers are lowercase.
const (
	ComponentMethod    = "@method"
	ComponentAuthority = "@authority"
	ComponentPath      = "@path"
	ComponentQuery     = "@query"

	ComponentContentDigest = "content-digest"
	ComponentContentType   = "content-type"

	ComponentAgentID          = "x-agent-id"
	ComponentTenantID         = "x-tenant-id"
	ComponentRequestID        = "x-request-id"
	ComponentSignatureVersion = "x-agent-signature-version"
	ComponentTraceParent      = "traceparent"
)

// ParamStrictSerialization is the RFC 9421 `sf` component parameter. It
// instructs the verifier to re-serialize the component as a strict structured
// field before comparison, which is what makes Content-Digest comparison
// insensitive to incidental whitespace.
const ParamStrictSerialization = "sf"

// coveredWithBody is the AGS1 covered component list for body-bearing
// requests, in exactly the order it must be signed.
var coveredWithBody = []string{
	ComponentMethod,
	ComponentAuthority,
	ComponentPath,
	ComponentQuery,
	ComponentContentDigest,
	ComponentContentType,
	ComponentAgentID,
	ComponentTenantID,
	ComponentRequestID,
	ComponentSignatureVersion,
	ComponentTraceParent,
}

// coveredWithoutBody is the AGS1 covered component list for body-less
// requests, in exactly the order it must be signed.
//
// RFC-0002 section 1 fixes an 11-component list while section 3 makes
// Content-Type and Content-Digest conditional on the request carrying a body.
// Those two statements cannot both hold for a GET. AGS1 v1 resolves the
// contradiction by defining two fixed profiles rather than one fixed list:
// a body-less request signs the same components minus content-digest and
// content-type. Both lists are closed sets, so a verifier can still reject any
// request whose declared components are not exactly one of them -- which is
// the property that actually matters for security.
var coveredWithoutBody = []string{
	ComponentMethod,
	ComponentAuthority,
	ComponentPath,
	ComponentQuery,
	ComponentAgentID,
	ComponentTenantID,
	ComponentRequestID,
	ComponentSignatureVersion,
	ComponentTraceParent,
}

// CoveredComponents returns the required AGS1 covered component list for a
// request, in signing order.
//
// The returned slice is a copy; callers may modify it freely.
func CoveredComponents(hasBody bool) []string {
	src := coveredWithoutBody
	if hasBody {
		src = coveredWithBody
	}

	out := make([]string, len(src))
	copy(out, src)
	return out
}

// IsSupportedComponent reports whether a component identifier is permitted
// anywhere in AGS1. It is a membership test, not a completeness test: use
// ValidateCoveredComponents to check that a declared list is exactly correct.
func IsSupportedComponent(component string) bool {
	switch component {
	case ComponentMethod,
		ComponentAuthority,
		ComponentPath,
		ComponentQuery,
		ComponentContentDigest,
		ComponentContentType,
		ComponentAgentID,
		ComponentTenantID,
		ComponentRequestID,
		ComponentSignatureVersion,
		ComponentTraceParent:
		return true
	default:
		return false
	}
}

// RequiresStrictSerialization reports whether a component must carry the `sf`
// parameter.
func RequiresStrictSerialization(component string) bool {
	return component == ComponentContentDigest
}
