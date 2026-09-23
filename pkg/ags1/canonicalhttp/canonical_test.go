package canonicalhttp_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Aryan22g/agw/pkg/ags1/canonicalhttp"
	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// TestQueryCanonicalForm covers the divergence RFC-0002 section 2 fixes:
// an absent query signs as "?" so it stays distinguishable from an empty one.
func TestQueryCanonicalForm(t *testing.T) {
	cases := map[string]string{
		"":           "?",
		"?":          "?",
		"a=1":        "?a=1",
		"?a=1":       "?a=1",
		"a=1&b=2":    "?a=1&b=2",
		"b=2&a=1":    "?b=2&a=1", // order preserved, never re-sorted
		"a=%2Fslash": "?a=%2Fslash",
		"empty=":     "?empty=",
	}

	for raw, want := range cases {
		if got := canonicalhttp.CanonicalQuery(raw); got != want {
			t.Errorf("CanonicalQuery(%q) = %q, want %q", raw, got, want)
		}
	}
}

// TestQueryOrderIsSignificant: a verifier that re-sorted parameters would
// accept a reordered query as equivalent, letting an attacker change
// parameter precedence downstream while keeping the signature valid.
func TestQueryOrderIsSignificant(t *testing.T) {
	a := canonicalhttp.CanonicalQuery("role=user&role=admin")
	b := canonicalhttp.CanonicalQuery("role=admin&role=user")
	if a == b {
		t.Error("query parameter order was normalized away")
	}
}

// TestPathEncodingPreserved: signing the decoded path would make /a%2Fb and
// /a/b identical to the verifier but distinct to the upstream.
func TestPathEncodingPreserved(t *testing.T) {
	encoded := httptest.NewRequest(http.MethodGet, "http://h/a%2Fb", nil)
	plain := httptest.NewRequest(http.MethodGet, "http://h/a/b", nil)

	ce, err := canonicalhttp.FromHTTPRequest(encoded, nil)
	if err != nil {
		t.Fatalf("encoded: %v", err)
	}
	cp, err := canonicalhttp.FromHTTPRequest(plain, nil)
	if err != nil {
		t.Fatalf("plain: %v", err)
	}

	if ce.Path == cp.Path {
		t.Errorf("percent-encoded and decoded paths canonicalized identically to %q", ce.Path)
	}
}

// TestDuplicateRequiredHeaderRejected: folding duplicates is where signature
// confusion lives, so AGS1 rejects them outright.
func TestDuplicateRequiredHeaderRejected(t *testing.T) {
	h := http.Header{}
	h.Add("X-Tenant-Id", "tenant-a")
	h.Add("X-Tenant-Id", "tenant-b")

	_, err := canonicalhttp.NormalizeHeaders(h)
	if !errors.Is(err, protocol.ErrDuplicateHeader) {
		t.Errorf("got %v, want ErrDuplicateHeader", err)
	}
}

func TestDuplicateNonRequiredHeaderFolded(t *testing.T) {
	h := http.Header{}
	h.Add("X-Custom", "one")
	h.Add("X-Custom", "two")

	out, err := canonicalhttp.NormalizeHeaders(h)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if out["x-custom"] != "one, two" {
		t.Errorf("got %q, want %q", out["x-custom"], "one, two")
	}
}

// TestObsFoldRemoved: a newline inside a header value would otherwise forge
// additional lines in the newline-delimited signature base.
func TestObsFoldRemoved(t *testing.T) {
	for _, in := range []string{
		"value\r\n continued",
		"value\n\"x-agent-id\": forged",
		"value\rmore",
	} {
		got := canonicalhttp.NormalizeHeaderValue(in)
		for _, r := range got {
			if r == '\n' || r == '\r' {
				t.Errorf("NormalizeHeaderValue(%q) = %q still contains a line break", in, got)
			}
		}
	}
}

func TestHeaderValueWhitespaceTrimmed(t *testing.T) {
	if got := canonicalhttp.NormalizeHeaderValue("   spaced   "); got != "spaced" {
		t.Errorf("got %q, want %q", got, "spaced")
	}
}

func TestAuthorityPrefersHost(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://ignored.example/x", nil)
	req.Host = "Real.Example.COM"

	c, err := canonicalhttp.FromHTTPRequest(req, nil)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if c.Authority != "real.example.com" {
		t.Errorf("authority = %q, want lowercased host", c.Authority)
	}
}

// TestComponentSetMustMatchProfile: the closure property that stops a signer
// shrinking what its signature covers.
func TestComponentSetMustMatchProfile(t *testing.T) {
	full := protocol.CoveredComponents(true)

	if err := canonicalhttp.ValidateCoveredComponents(full, true); err != nil {
		t.Fatalf("the correct component set was rejected: %v", err)
	}

	// Too few.
	if err := canonicalhttp.ValidateCoveredComponents(full[:5], true); !errors.Is(err, protocol.ErrComponentSetMismatch) {
		t.Errorf("truncated set: got %v, want ErrComponentSetMismatch", err)
	}

	// Right members, wrong order.
	swapped := append([]string(nil), full...)
	swapped[0], swapped[1] = swapped[1], swapped[0]
	if err := canonicalhttp.ValidateCoveredComponents(swapped, true); !errors.Is(err, protocol.ErrComponentSetMismatch) {
		t.Errorf("reordered set: got %v, want ErrComponentSetMismatch", err)
	}

	// Body-less profile used for a body-bearing request.
	if err := canonicalhttp.ValidateCoveredComponents(protocol.CoveredComponents(false), true); err == nil {
		t.Error("the body-less component set was accepted for a body-bearing request")
	}
}

func TestUnsupportedComponentRejected(t *testing.T) {
	bad := protocol.CoveredComponents(true)
	bad[6] = "x-attacker-controlled"

	if err := canonicalhttp.ValidateCoveredComponents(bad, true); err == nil {
		t.Error("an unsupported component was accepted")
	}
}

func TestMissingCoveredHeaderRejected(t *testing.T) {
	req := &canonicalhttp.CanonicalRequest{
		Method: "GET", Authority: "h", Path: "/", Query: "?",
		Headers: map[string]string{}, // no x-agent-id
	}

	_, err := canonicalhttp.BuildSignatureBase(req, protocol.CoveredComponents(false),
		canonicalhttp.SignatureParams{Created: 1, KeyID: "k", Nonce: "n", Tag: protocol.SignatureTag})
	if !errors.Is(err, protocol.ErrMissingCoveredComponent) {
		t.Errorf("got %v, want ErrMissingCoveredComponent", err)
	}
}

// TestSignatureParamsLineIsLast: the params line binds the component list to
// the signature; if it were not last, a component line could be stripped.
func TestSignatureParamsLineIsLast(t *testing.T) {
	req := &canonicalhttp.CanonicalRequest{
		Method: "GET", Authority: "h", Path: "/", Query: "?",
		Headers: map[string]string{
			"x-agent-id": "a", "x-tenant-id": "t", "x-request-id": "r",
			"x-agent-signature-version": "1", "traceparent": "tp",
		},
	}

	base, err := canonicalhttp.BuildSignatureBase(req, protocol.CoveredComponents(false),
		canonicalhttp.SignatureParams{Created: 1, KeyID: "k", Nonce: "n", Tag: protocol.SignatureTag})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	lines := splitLines(string(base))
	last := lines[len(lines)-1]
	if len(last) < 20 || last[:20] != `"@signature-params":` {
		t.Errorf("last line is %q, want the @signature-params line", last)
	}
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}
