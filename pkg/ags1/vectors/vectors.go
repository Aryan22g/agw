// Package vectors defines the AGS1 conformance corpus.
//
// Every AGS1 SDK, in any language, must reproduce these vectors exactly. They
// are the operational definition of the profile: RFC-0002 states the rules in
// prose, and these files state what those rules produce for concrete input.
//
// Vectors are generated from pkg/ags1 by `go generate ./pkg/ags1/vectors`.
// The previous corpus was generated from an implementation that had drifted
// from the RFC, so it locked the drift in rather than catching it. Regenerate
// only when the profile version changes, and review the diff: an unexpected
// change here is a wire-breaking change.
package vectors

// Vector is one conformance case.
type Vector struct {
	Name        string `json:"name"`
	Description string `json:"description"`

	// Request.
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body,omitempty"`
	ContentType string            `json:"contentType,omitempty"`

	// Identity.
	TenantID string `json:"tenantId"`
	AgentID  string `json:"agentId"`

	// Key material, base64 (standard, padded).
	PrivateKey string `json:"privateKey"`
	PublicKey  string `json:"publicKey"`
	KeyID      string `json:"keyId"`

	// Signing inputs pinned so the result is reproducible.
	Nonce     string `json:"nonce"`
	RequestID string `json:"requestId"`
	Trace     string `json:"traceparent"`
	Created   int64  `json:"created"`

	// Expected outputs. An SDK is conformant when it produces these bytes.
	CanonicalBody  string `json:"canonicalBody,omitempty"`
	ContentDigest  string `json:"contentDigest,omitempty"`
	SignatureInput string `json:"signatureInput"`
	SignatureBase  string `json:"signatureBase"`
	Signature      string `json:"signature"`

	// Verify records whether a conformant verifier accepts this vector, and
	// why not when it does not.
	Verify VerifyExpectation `json:"verify"`
}

// VerifyExpectation is the expected verifier outcome.
type VerifyExpectation struct {
	Accepted bool `json:"accepted"`

	// Reason is a stable slug describing the rejection, empty when accepted.
	Reason string `json:"reason,omitempty"`

	// NowUnix is the verification time to use, so time-dependent vectors are
	// reproducible.
	NowUnix int64 `json:"nowUnix"`
}

// Corpus is a full vector file.
type Corpus struct {
	Profile string   `json:"profile"`
	Version string   `json:"version"`
	Tag     string   `json:"tag"`
	Vectors []Vector `json:"vectors"`
}
