package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// KeyPair is an AGS1 Ed25519 keypair together with its derived kid.
type KeyPair struct {
	KeyID      string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
}

// Generate creates a new AGS1 keypair using crypto/rand.
func Generate() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	kid, err := KeyID(pub)
	if err != nil {
		return nil, err
	}

	return &KeyPair{KeyID: kid, PublicKey: pub, PrivateKey: priv}, nil
}

// Sign signs a signature base with an Ed25519 private key.
func Sign(priv ed25519.PrivateKey, signatureBase []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d",
			protocol.ErrInvalidPrivateKey, len(priv), ed25519.PrivateKeySize)
	}
	if len(signatureBase) == 0 {
		return nil, protocol.ErrMalformedSignatureInput
	}
	return ed25519.Sign(priv, signatureBase), nil
}

// Verify checks an Ed25519 signature over a signature base.
//
// Length checks come first so that a malformed key or signature produces a
// precise error instead of a bare "verification failed", which makes
// misconfiguration debuggable without weakening the failure path: every
// route out of this function that is not an explicit nil is a rejection.
func Verify(pub ed25519.PublicKey, signatureBase, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: got %d bytes, want %d",
			protocol.ErrInvalidPublicKey, len(pub), ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d",
			protocol.ErrSignatureInvalid, len(signature), ed25519.SignatureSize)
	}
	if len(signatureBase) == 0 {
		return fmt.Errorf("%w: empty signature base", protocol.ErrSignatureInvalid)
	}

	if !ed25519.Verify(pub, signatureBase, signature) {
		return protocol.ErrSignatureInvalid
	}
	return nil
}

// EncodePrivateKey encodes a private key as base64 (standard, padded) for
// storage in a keystore file.
//
// This is an encoding, not protection. Callers are responsible for at-rest
// encryption and file permissions; see the SDK keystore.
func EncodePrivateKey(priv ed25519.PrivateKey) string {
	return base64.StdEncoding.EncodeToString(priv)
}

// DecodePrivateKey parses a base64-encoded Ed25519 private key.
func DecodePrivateKey(encoded string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", protocol.ErrInvalidPrivateKey, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d",
			protocol.ErrInvalidPrivateKey, len(raw), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(raw), nil
}

// DecodePublicKey parses a base64 (standard, padded) Ed25519 public key.
func DecodePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", protocol.ErrInvalidPublicKey, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: got %d bytes, want %d",
			protocol.ErrInvalidPublicKey, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}
