package keys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// ThumbprintInput builds the RFC 7638 canonical thumbprint input for an AGS1
// key.
//
// RFC 7638 requires a JSON object containing only the REQUIRED members for
// the key type, with lexicographically ordered keys, no whitespace, and no
// insignificant characters. For an OKP key those members are exactly crv,
// kty and x -- in that order, which is already lexicographic.
//
// This is built by hand rather than with encoding/json on purpose. A struct
// marshal would be at the mercy of field ordering, optional members and
// HTML escaping; the thumbprint is a key identifier, so its byte-level
// stability across languages is the whole point. Every AGS1 SDK must produce
// these exact bytes.
func ThumbprintInput(x string) []byte {
	return []byte(`{"crv":"` + CurveEd25519 + `","kty":"` + KeyTypeOKP + `","x":"` + x + `"}`)
}

// Thumbprint computes the RFC 7638 thumbprint of the JWK, base64url-encoded
// without padding. This value is the AGS1 `kid`.
func (j *JWK) Thumbprint() (string, error) {
	if j == nil {
		return "", protocol.ErrInvalidJWK
	}
	if j.Kty != KeyTypeOKP || j.Crv != CurveEd25519 {
		return "", fmt.Errorf("%w: thumbprint is defined only for OKP/Ed25519",
			protocol.ErrInvalidJWK)
	}
	if j.X == "" {
		return "", fmt.Errorf("%w: missing x", protocol.ErrInvalidJWK)
	}

	sum := sha256.Sum256(ThumbprintInput(j.X))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// KeyID derives the AGS1 kid directly from an Ed25519 public key.
//
// This is the canonical way to name a credential. Registration, JWKS
// publication and signature verification must all agree on it.
func KeyID(pub ed25519.PublicKey) (string, error) {
	jwk, err := PublicKeyToJWK(pub)
	if err != nil {
		return "", err
	}
	return jwk.Kid, nil
}
