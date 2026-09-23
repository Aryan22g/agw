package canonicalhttp

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// NormalizeHeaders converts an http.Header into the lowercase single-valued
// map the signature base is built from.
//
// AGS1 rejects duplicate instances of its required headers instead of folding
// them into a comma-joined value. RFC 9421 permits folding, but folding is
// exactly where signature confusion lives: an intermediary that folds in a
// different order than the verifier, or that folds where the signer did not,
// changes the signature base for identical wire bytes. Since AGS1 controls
// both ends, rejecting is strictly safer and costs nothing.
//
// Non-required headers with multiple values are folded with ", " because they
// are not covered components and cannot affect the signature base.
func NormalizeHeaders(h http.Header) (map[string]string, error) {
	if h == nil {
		return map[string]string{}, nil
	}

	out := make(map[string]string, len(h))

	for name, values := range h {
		if len(values) == 0 {
			continue
		}

		if len(values) > 1 && protocol.IsSingletonHeader(name) {
			return nil, fmt.Errorf("%w: %s appears %d times",
				protocol.ErrDuplicateHeader, strings.ToLower(name), len(values))
		}

		cleaned := make([]string, 0, len(values))
		for _, v := range values {
			cleaned = append(cleaned, NormalizeHeaderValue(v))
		}

		out[strings.ToLower(name)] = strings.Join(cleaned, ", ")
	}

	return out, nil
}

// NormalizeHeaderValue applies RFC 9421 field value normalization: strip
// leading and trailing optional whitespace, and remove obs-fold.
//
// obs-fold (a CRLF followed by whitespace inside a value) is obsolete in
// HTTP/1.1 and absent in HTTP/2, but a value carrying one would otherwise put
// a bare newline into the signature base -- and the base is newline-delimited,
// so that would let a crafted header value forge additional component lines.
func NormalizeHeaderValue(v string) string {
	if strings.ContainsAny(v, "\r\n") {
		v = strings.ReplaceAll(v, "\r\n", " ")
		v = strings.ReplaceAll(v, "\r", " ")
		v = strings.ReplaceAll(v, "\n", " ")

		for strings.Contains(v, "  ") {
			v = strings.ReplaceAll(v, "  ", " ")
		}
	}
	return strings.TrimSpace(v)
}

// NormalizeHeaderName lowercases and trims a header name.
func NormalizeHeaderName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
