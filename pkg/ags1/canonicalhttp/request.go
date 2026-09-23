// Package canonicalhttp turns an HTTP request into the deterministic byte
// string that AGS1 signs and verifies.
//
// Everything here is byte-exact by design. If a signer and a verifier disagree
// about a single space, the signature fails; if they agree about the wrong
// bytes, the signature proves nothing. That is why normalization rules live in
// one package that both the gateway and the SDKs import, rather than being
// re-derived per implementation.
package canonicalhttp

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// CanonicalRequest is the normalized view of an HTTP request that the
// signature base is built from.
//
// Construct it with FromHTTPRequest rather than by hand wherever a real
// *http.Request is available, so that normalization is applied consistently.
type CanonicalRequest struct {
	// Method is the HTTP method, uppercase.
	Method string

	// Authority is the host[:port] the request was addressed to.
	//
	// AGS1 signs @authority rather than the Host header, so that a request
	// stays verifiable across proxies that rewrite Host.
	Authority string

	// Path is the percent-encoded absolute path, with no query string.
	Path string

	// Query is the raw query string INCLUDING its leading '?', or exactly
	// "?" when the request carries no query.
	//
	// Keeping the leading '?' and never re-encoding is deliberate: a
	// verifier that parsed and re-emitted parameters would silently accept
	// a reordered or re-encoded query as equivalent, which lets an attacker
	// alter parameter precedence downstream while keeping the signature
	// valid.
	Query string

	// Headers holds lowercase header names mapped to their single
	// normalized value.
	Headers map[string]string

	// Body is the exact transmitted body bytes, or nil for a body-less
	// request.
	Body []byte
}

// HasBody reports whether this request carries a body, which selects the
// AGS1 covered component profile.
func (r *CanonicalRequest) HasBody() bool {
	return r != nil && len(r.Body) > 0
}

// FromHTTPRequest builds a CanonicalRequest from a server-side *http.Request
// and its already-read body.
//
// The body must be supplied separately because reading it is destructive and
// the caller needs those same bytes to forward upstream.
func FromHTTPRequest(r *http.Request, body []byte) (*CanonicalRequest, error) {
	if r == nil || r.URL == nil {
		return nil, protocol.ErrNilRequest
	}

	headers, err := NormalizeHeaders(r.Header)
	if err != nil {
		return nil, err
	}

	return &CanonicalRequest{
		Method:    strings.ToUpper(strings.TrimSpace(r.Method)),
		Authority: canonicalAuthority(r),
		Path:      canonicalPath(r.URL),
		Query:     CanonicalQuery(r.URL.RawQuery),
		Headers:   headers,
		Body:      body,
	}, nil
}

// CanonicalQuery renders a raw query string in AGS1 form.
//
// An absent query is signed as "?" rather than as the empty string. Without a
// distinct marker, "no query" and "empty query" would produce the same
// signature base, letting a request signed with neither be replayed with an
// empty one appended.
func CanonicalQuery(raw string) string {
	raw = strings.TrimPrefix(raw, "?")
	if raw == "" {
		return "?"
	}
	return "?" + raw
}

// canonicalAuthority resolves the @authority component.
//
// r.Host is preferred over r.URL.Host because on a server-side request the
// URL is usually origin-form and carries no host at all.
func canonicalAuthority(r *http.Request) string {
	if h := strings.TrimSpace(r.Host); h != "" {
		return strings.ToLower(h)
	}
	if r.URL != nil {
		return strings.ToLower(strings.TrimSpace(r.URL.Host))
	}
	return ""
}

// canonicalPath resolves the @path component, preserving percent-encoding.
//
// EscapedPath returns the encoding as it arrived on the wire where that is a
// valid encoding of the decoded path. Signing the decoded path instead would
// make "/a%2Fb" and "/a/b" identical to the verifier while remaining distinct
// to the upstream service -- a path confusion bypass.
func canonicalPath(u *url.URL) string {
	if u == nil {
		return ""
	}
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	return p
}
