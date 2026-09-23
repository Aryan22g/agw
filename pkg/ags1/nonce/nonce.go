// Package nonce generates and validates AGS1 replay-protection nonces.
package nonce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// DefaultBytes is the nonce entropy AGS1 SDKs emit: 32 bytes, encoded as 43
// base64url characters. That is comfortably above the 128-bit floor and sits
// inside the 22-64 character range the profile permits.
const DefaultBytes = 32

// New returns a fresh base64url-nopad nonce with DefaultBytes of entropy.
func New() (string, error) {
	return NewWithBytes(DefaultBytes)
}

// NewWithBytes returns a fresh nonce with n bytes of entropy.
func NewWithBytes(n int) (string, error) {
	if n < protocol.NonceMinBytes {
		return "", fmt.Errorf("%w: %d bytes requested, minimum is %d",
			protocol.ErrNonceTooShort, n, protocol.NonceMinBytes)
	}

	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// Validate checks a received nonce against the AGS1 charset and length rules.
//
// This runs before the nonce reaches the replay store. An unvalidated nonce is
// attacker-controlled input that becomes part of a storage key, so bounding
// its length and charset here keeps key construction predictable and stops a
// caller from burning replay-store capacity with oversized values.
func Validate(n string) error {
	if len(n) < protocol.NonceMinChars {
		return fmt.Errorf("%w: %d characters, minimum is %d",
			protocol.ErrNonceTooShort, len(n), protocol.NonceMinChars)
	}
	if len(n) > protocol.NonceMaxChars {
		return fmt.Errorf("%w: %d characters, maximum is %d",
			protocol.ErrNonceTooLong, len(n), protocol.NonceMaxChars)
	}

	for _, r := range n {
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '-', r == '_':
		default:
			return fmt.Errorf("%w: %q", protocol.ErrNonceCharset, r)
		}
	}

	return nil
}

// Hash returns the base64url-nopad SHA-256 of a nonce.
//
// The replay store holds only this hash (RFC-0002 section 11). A dump of the
// replay store therefore does not hand an attacker a set of live nonces, and
// keys stay fixed-width regardless of nonce length.
func Hash(n string) string {
	sum := sha256.Sum256([]byte(n))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ReplayKey builds the AGS1 replay reservation key (RFC-0002 section 12):
//
//	replay:v1:{tenant_id}:{credential_id}:{sha256b64u(nonce)}
//
// The tenant is part of the key so that two tenants cannot collide on a nonce
// value, and the credential is part of it so that rotating a key does not
// inherit the previous key's reservation history.
func ReplayKey(tenantID, credentialID, n string) string {
	return fmt.Sprintf("replay:v1:%s:%s:%s",
		sanitize(tenantID), sanitize(credentialID), Hash(n))
}

// sanitize makes an identifier safe to embed in a colon-delimited key.
//
// Without this, an identifier containing ':' could shift the meaning of the
// key and let one tenant address another tenant's reservation namespace.
func sanitize(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	return strings.ReplaceAll(v, ":", "_")
}
