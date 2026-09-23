package httpmsig

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// NewTraceParent generates a W3C traceparent value.
//
// AGS1 signs traceparent so that the trace identity a request claims cannot be
// swapped after signing, which is what makes the audit trail joinable to
// distributed traces without trusting the caller.
func NewTraceParent() (string, error) {
	var traceID [16]byte
	var spanID [8]byte

	if _, err := rand.Read(traceID[:]); err != nil {
		return "", fmt.Errorf("generate trace id: %w", err)
	}
	if _, err := rand.Read(spanID[:]); err != nil {
		return "", fmt.Errorf("generate span id: %w", err)
	}

	return fmt.Sprintf("00-%s-%s-01",
		hex.EncodeToString(traceID[:]),
		hex.EncodeToString(spanID[:]),
	), nil
}

// SetRequestBody replaces a request body and keeps ContentLength and GetBody
// consistent with it.
//
// GetBody matters for redirects and retries: without it net/http cannot replay
// the body, and a replayed request with a missing body would fail its own
// content-digest check.
func SetRequestBody(r *http.Request, body []byte) {
	if r == nil {
		return
	}

	if len(body) == 0 {
		r.Body = http.NoBody
		r.ContentLength = 0
		r.GetBody = func() (io.ReadCloser, error) { return http.NoBody, nil }
		return
	}

	buf := append([]byte(nil), body...)
	r.Body = io.NopCloser(bytes.NewReader(buf))
	r.ContentLength = int64(len(buf))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(buf)), nil
	}
}

// isJSONContentType reports whether a Content-Type denotes JSON, and therefore
// whether the body must be JCS-canonicalized before signing.
func isJSONContentType(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}

	return ct == "application/json" ||
		strings.HasSuffix(ct, "+json")
}
