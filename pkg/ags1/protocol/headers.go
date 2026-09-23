package protocol

import "net/textproto"

// Canonical AGS1 header names, lowercase.
//
// Component identifiers in Signature-Input MUST be lowercase (RFC-0002
// section 2), so these constants are the lowercase form. Use HTTPName when
// setting a header on a Go *http.Request, which canonicalizes to MIME casing.
const (
	HeaderAgentID          = "x-agent-id"
	HeaderTenantID         = "x-tenant-id"
	HeaderRequestID        = "x-request-id"
	HeaderSignatureVersion = "x-agent-signature-version"
	HeaderTraceParent      = "traceparent"

	HeaderContentType   = "content-type"
	HeaderContentDigest = "content-digest"

	HeaderSignature      = "signature"
	HeaderSignatureInput = "signature-input"
)

// requiredHeadersAlways are required on every AGS1 request regardless of
// whether it carries a body.
var requiredHeadersAlways = []string{
	HeaderAgentID,
	HeaderTenantID,
	HeaderRequestID,
	HeaderSignatureVersion,
	HeaderTraceParent,
	HeaderSignature,
	HeaderSignatureInput,
}

// requiredHeadersWithBody are additionally required on body-bearing requests.
var requiredHeadersWithBody = []string{
	HeaderContentType,
	HeaderContentDigest,
}

// RequiredHeaders returns the headers that MUST be present on an AGS1
// request. The returned slice is a copy.
func RequiredHeaders(hasBody bool) []string {
	out := make([]string, 0, len(requiredHeadersAlways)+len(requiredHeadersWithBody))
	out = append(out, requiredHeadersAlways...)
	if hasBody {
		out = append(out, requiredHeadersWithBody...)
	}
	return out
}

// IsSingletonHeader reports whether a header must appear exactly once.
//
// AGS1 rejects duplicate instances of every required header rather than
// folding them with ", ". Folding is the root of a whole class of request
// smuggling and signature confusion attacks: a proxy that folds differently
// from the verifier produces a different signature base for the same bytes.
func IsSingletonHeader(name string) bool {
	switch textproto.CanonicalMIMEHeaderKey(name) {
	case textproto.CanonicalMIMEHeaderKey(HeaderAgentID),
		textproto.CanonicalMIMEHeaderKey(HeaderTenantID),
		textproto.CanonicalMIMEHeaderKey(HeaderRequestID),
		textproto.CanonicalMIMEHeaderKey(HeaderSignatureVersion),
		textproto.CanonicalMIMEHeaderKey(HeaderTraceParent),
		textproto.CanonicalMIMEHeaderKey(HeaderContentType),
		textproto.CanonicalMIMEHeaderKey(HeaderContentDigest),
		textproto.CanonicalMIMEHeaderKey(HeaderSignature),
		textproto.CanonicalMIMEHeaderKey(HeaderSignatureInput):
		return true
	default:
		return false
	}
}

// HTTPName converts a lowercase AGS1 header name to Go's canonical MIME
// casing, for use with http.Header.
func HTTPName(name string) string {
	return textproto.CanonicalMIMEHeaderKey(name)
}
