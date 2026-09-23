package httpmsig

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/canonicalhttp"
	"github.com/Aryan22g/agw/pkg/ags1/digest"
	"github.com/Aryan22g/agw/pkg/ags1/nonce"
	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// VerifyInput is one request to be cryptographically verified.
//
// This is pure Stage-1 work: it answers "were these exact bytes signed by the
// private key matching this public key, recently, under this profile?" and
// nothing else. It deliberately knows nothing about tenants, credentials,
// revocation or authorization -- those are separate decisions with separate
// failure modes, and conflating them is what makes a verifier hard to audit.
type VerifyInput struct {
	Request *canonicalhttp.CanonicalRequest

	SignatureInputHeader string
	SignatureHeader      string

	// PublicKey is resolved by the caller from the parsed keyid.
	PublicKey ed25519.PublicKey

	// Now defaults to time.Now().UTC().
	Now time.Time

	// MaxAge and MaxSkew default to the AGS1 profile values.
	MaxAge  time.Duration
	MaxSkew time.Duration
}

// VerifyResult reports what a successful verification established.
type VerifyResult struct {
	KeyID         string
	Nonce         string
	Created       time.Time
	Components    []string
	SignatureBase []byte
}

// ParseHeaders parses and validates the signature headers without performing
// cryptographic verification.
//
// The gateway needs the keyid before it can resolve a public key, so parsing
// has to be callable on its own. Nothing this returns is trustworthy until
// Verify succeeds.
func ParseHeaders(signatureInputHeader, signatureHeader string) (*SignatureInput, []byte, error) {
	input, err := ParseSignatureInput(signatureInputHeader)
	if err != nil {
		return nil, nil, err
	}

	sigLabel, signature, err := ParseSignatureHeader(signatureHeader)
	if err != nil {
		return nil, nil, err
	}

	if err := MatchLabel(input.Label, sigLabel); err != nil {
		return nil, nil, err
	}

	if err := nonce.Validate(input.Params.Nonce); err != nil {
		return nil, nil, err
	}

	return input, signature, nil
}

// Verify performs full AGS1 cryptographic verification of a request.
//
// Checks run cheapest-first, but every one of them is a hard rejection: there
// is no path through this function that returns success with a check skipped.
func Verify(in VerifyInput) (*VerifyResult, error) {
	if in.Request == nil {
		return nil, protocol.ErrNilRequest
	}

	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	maxAge := in.MaxAge
	if maxAge <= 0 {
		maxAge = protocol.MaxRequestAgeSeconds * time.Second
	}
	maxSkew := in.MaxSkew
	if maxSkew <= 0 {
		maxSkew = protocol.MaxClockSkewSeconds * time.Second
	}

	input, signature, err := ParseHeaders(in.SignatureInputHeader, in.SignatureHeader)
	if err != nil {
		return nil, err
	}

	// The declared component set must be exactly the AGS1 profile for this
	// request shape. Checked before the signature so a caller cannot use a
	// truncated component list to shrink what the signature covers.
	if err := canonicalhttp.ValidateCoveredComponents(input.Components, in.Request.HasBody()); err != nil {
		return nil, err
	}

	created := time.Unix(input.Params.Created, 0).UTC()
	if err := ValidateTimestamp(created, now, maxAge, maxSkew); err != nil {
		return nil, err
	}

	// Verify the digest against the actual body before spending a signature
	// verification on it, and so that a body/digest mismatch reports as a
	// digest failure rather than a confusing signature failure.
	if in.Request.HasBody() {
		provided, ok := in.Request.Headers[protocol.HeaderContentDigest]
		if !ok {
			return nil, fmt.Errorf("%w: %s", protocol.ErrMissingRequiredHeader,
				protocol.HeaderContentDigest)
		}
		if err := digest.Validate(in.Request.Body, provided); err != nil {
			return nil, err
		}
	}

	base, err := canonicalhttp.BuildSignatureBase(in.Request, input.Components, input.Params)
	if err != nil {
		return nil, err
	}

	if err := verifyEd25519(in.PublicKey, base, signature); err != nil {
		return nil, err
	}

	return &VerifyResult{
		KeyID:         input.Params.KeyID,
		Nonce:         input.Params.Nonce,
		Created:       created,
		Components:    input.Components,
		SignatureBase: base,
	}, nil
}

// ValidateTimestamp enforces the AGS1 acceptance window.
//
// Two separate bounds, not one: MaxAge stops an old captured request from
// being replayed after its nonce reservation has expired, while MaxSkew bounds
// how far a client clock may run ahead. A single symmetric window would force
// a trade-off between tolerating clock drift and shrinking the replay window.
func ValidateTimestamp(created, now time.Time, maxAge, maxSkew time.Duration) error {
	if created.IsZero() {
		return protocol.ErrMissingCreated
	}

	if created.After(now.Add(maxSkew)) {
		return fmt.Errorf("%w: created %s is %s ahead of now, limit is %s",
			protocol.ErrRequestNotYetValid,
			created.Format(time.RFC3339),
			created.Sub(now).Truncate(time.Second),
			maxSkew)
	}

	if age := now.Sub(created); age > maxAge {
		return fmt.Errorf("%w: created %s is %s old, limit is %s",
			protocol.ErrRequestExpired,
			created.Format(time.RFC3339),
			age.Truncate(time.Second),
			maxAge)
	}

	return nil
}

func verifyEd25519(pub ed25519.PublicKey, base, signature []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: got %d bytes, want %d",
			protocol.ErrInvalidPublicKey, len(pub), ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d",
			protocol.ErrSignatureInvalid, len(signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, base, signature) {
		return protocol.ErrSignatureInvalid
	}
	return nil
}
