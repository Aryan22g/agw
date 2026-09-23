// Package keys implements AGS1 v1 key handling: Ed25519 keypairs, their JWK
// representation, and RFC 7638 thumbprint-derived key identifiers.
package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// JWK constants fixed by AGS1 v1 (RFC-0002 section 8).
const (
	KeyTypeOKP   = "OKP"
	CurveEd25519 = "Ed25519"
)

// JWK is an AGS1 public key in JWK form.
//
// AGS1 v1 permits exactly one key shape: an OKP key on curve Ed25519. The
// struct is intentionally narrow -- a permissive JWK parser is an attack
// surface, because it lets a caller present a key of a type the verifier did
// not intend to support.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`

	// Kid is the RFC 7638 thumbprint. It is derived, never supplied: any
	// value present on input is checked against the derivation, not trusted.
	Kid string `json:"kid,omitempty"`

	// Use and Alg are advisory metadata for JWKS consumers.
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// PublicKeyToJWK builds an AGS1 JWK from an Ed25519 public key, deriving the
// kid from the key material.
func PublicKeyToJWK(pub ed25519.PublicKey) (*JWK, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d",
			protocol.ErrInvalidPublicKey, len(pub), ed25519.PublicKeySize)
	}

	jwk := &JWK{
		Kty: KeyTypeOKP,
		Crv: CurveEd25519,
		X:   base64.RawURLEncoding.EncodeToString(pub),
		Use: "sig",
		Alg: "EdDSA",
	}

	kid, err := jwk.Thumbprint()
	if err != nil {
		return nil, err
	}
	jwk.Kid = kid

	return jwk, nil
}

// PublicKey decodes the JWK back into raw Ed25519 key material, validating
// the key shape as it goes.
func (j *JWK) PublicKey() (ed25519.PublicKey, error) {
	if j == nil {
		return nil, protocol.ErrInvalidJWK
	}
	if j.Kty != KeyTypeOKP {
		return nil, fmt.Errorf("%w: kty must be %q, got %q",
			protocol.ErrInvalidJWK, KeyTypeOKP, j.Kty)
	}
	if j.Crv != CurveEd25519 {
		return nil, fmt.Errorf("%w: crv must be %q, got %q",
			protocol.ErrInvalidJWK, CurveEd25519, j.Crv)
	}
	if strings.TrimSpace(j.X) == "" {
		return nil, fmt.Errorf("%w: missing x", protocol.ErrInvalidJWK)
	}

	raw, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("%w: x is not base64url-nopad: %v",
			protocol.ErrInvalidJWK, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: x decodes to %d bytes, want %d",
			protocol.ErrInvalidPublicKey, len(raw), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(raw), nil
}

// Validate checks the JWK is a well-formed AGS1 key and that any supplied kid
// matches the derived thumbprint.
//
// The kid check matters: kid is the lookup key the verifier uses to find a
// credential. If a kid could name a key whose material hashes to something
// else, an attacker could point a valid signature at the wrong credential.
func (j *JWK) Validate() error {
	if _, err := j.PublicKey(); err != nil {
		return err
	}

	derived, err := j.Thumbprint()
	if err != nil {
		return err
	}

	if j.Kid != "" && j.Kid != derived {
		return fmt.Errorf("%w: kid=%q derived=%q",
			protocol.ErrKeyIDMismatch, j.Kid, derived)
	}

	return nil
}

// MarshalJSON is not overridden; the struct tags already produce the required
// shape. ThumbprintInput below builds the RFC 7638 form separately, because
// the thumbprint is computed over a strict three-member subset rather than
// over the full JWK.

// jwksKey mirrors JWK for JWKS documents.
type jwksKey = JWK

// JWKS is a JSON Web Key Set as served from /.well-known/ags1/jwks.json.
type JWKS struct {
	Keys []jwksKey `json:"keys"`
}

// ParseJWK decodes and validates a single JWK from JSON.
func ParseJWK(data []byte) (*JWK, error) {
	var j JWK
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("%w: %v", protocol.ErrInvalidJWK, err)
	}
	if err := j.Validate(); err != nil {
		return nil, err
	}
	return &j, nil
}
