// Package digest implements the RFC 9530 Content-Digest handling AGS1
// requires.
package digest

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// AGS1 v1 supports exactly one digest algorithm. A verifier that accepts a
// client-selected algorithm can be talked down to the weakest one it knows,
// so the set is closed rather than negotiated.
const (
	AlgorithmSHA256 = "sha-256"

	prefix = AlgorithmSHA256 + "=:"
	suffix = ":"
)

// Compute returns the AGS1 Content-Digest header value for the exact bytes
// that will be transmitted:
//
//	sha-256=:BASE64(SHA256(body)):
//
// The caller must pass the transmitted bytes. For a JSON body that means the
// JCS output, not the pre-canonicalization source.
func Compute(body []byte) string {
	sum := sha256.Sum256(body)
	return prefix + base64.StdEncoding.EncodeToString(sum[:]) + suffix
}

// Parse extracts the base64 digest from a Content-Digest header value.
func Parse(value string) (string, error) {
	value = strings.TrimSpace(value)

	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, suffix) {
		return "", fmt.Errorf("%w: expected sha-256=:<base64>: form, got %q",
			protocol.ErrInvalidContentDigest, value)
	}

	inner := strings.TrimSuffix(strings.TrimPrefix(value, prefix), suffix)
	if inner == "" {
		return "", fmt.Errorf("%w: empty digest", protocol.ErrInvalidContentDigest)
	}
	if _, err := base64.StdEncoding.DecodeString(inner); err != nil {
		return "", fmt.Errorf("%w: digest is not valid base64: %v",
			protocol.ErrInvalidContentDigest, err)
	}

	return inner, nil
}

// Validate checks that a Content-Digest header value matches the body bytes.
//
// The comparison is constant-time. Digest comparison sits before signature
// verification in the pipeline, so a timing side channel here would leak
// information about the expected digest to an unauthenticated caller.
func Validate(body []byte, provided string) error {
	if _, err := Parse(provided); err != nil {
		return err
	}

	expected := Compute(body)
	if subtle.ConstantTimeCompare([]byte(expected), []byte(strings.TrimSpace(provided))) != 1 {
		return protocol.ErrContentDigestMismatch
	}
	return nil
}

// Normalize re-serializes a Content-Digest value into its strict structured
// field form, which is what the `sf` component parameter calls for.
//
// AGS1 permits exactly one algorithm and one member, so normalization reduces
// to validating the shape and emitting the canonical spelling. Whitespace a
// proxy may have introduced around the value is discarded.
func Normalize(value string) (string, error) {
	inner, err := Parse(value)
	if err != nil {
		return "", err
	}
	return prefix + inner + suffix, nil
}
