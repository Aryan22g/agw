package keys

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// ProofPurpose binds a proof of possession to what it is being used for, so a
// proof minted for one operation cannot be presented for another.
const ProofPurpose = "ags1-credential-registration-v1"

// ProofMaxAge bounds how long a registration proof stays acceptable.
const ProofMaxAge = 5 * time.Minute

// ProofInput builds the exact bytes a registration proof signs.
//
// The encoding is length-prefixed rather than delimiter-joined: an identifier
// containing the delimiter could otherwise shift the field boundaries and let
// one proof read as a proof for a different tenant, agent or key.
//
// The key id is included, so a proof is inseparable from the specific key it
// registers. That is what makes replaying a captured proof useless: replaying
// it can only re-register the same key for the same agent.
func ProofInput(tenantID, agentID, keyID string, issuedAt time.Time) []byte {
	var b strings.Builder
	b.WriteString(ProofPurpose)
	b.WriteString("\n")

	for _, field := range []string{
		tenantID,
		agentID,
		keyID,
		fmt.Sprintf("%d", issuedAt.UTC().Unix()),
	} {
		fmt.Fprintf(&b, "%d:%s", len(field), field)
	}

	return []byte(b.String())
}

// SignProof produces a proof of possession for a credential registration.
//
// The registrant demonstrates it holds the private key matching the public key
// it is submitting. Without this, an operator could register a public key they
// do not control -- by mistake or because they were given one -- creating a
// credential that names an agent nobody can actually act as, or worse, one an
// attacker supplied.
func SignProof(priv ed25519.PrivateKey, tenantID, agentID, keyID string, issuedAt time.Time) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("%w: got %d bytes, want %d",
			protocol.ErrInvalidPrivateKey, len(priv), ed25519.PrivateKeySize)
	}

	sig := ed25519.Sign(priv, ProofInput(tenantID, agentID, keyID, issuedAt))
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifyProof checks a registration proof against the public key being
// registered.
//
// The freshness window bounds how long a captured proof stays usable. It is
// secondary to the key binding above, but it keeps an old proof from being
// replayed long after the operator intended the registration.
func VerifyProof(pub ed25519.PublicKey, tenantID, agentID, keyID, proof string, issuedAt, now time.Time) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: got %d bytes, want %d",
			protocol.ErrInvalidPublicKey, len(pub), ed25519.PublicKeySize)
	}

	if issuedAt.IsZero() {
		return fmt.Errorf("proof of possession: missing issuedAt")
	}
	if age := now.Sub(issuedAt); age > ProofMaxAge {
		return fmt.Errorf("proof of possession: issued %s ago, limit is %s",
			age.Truncate(time.Second), ProofMaxAge)
	}
	if issuedAt.After(now.Add(ProofMaxAge)) {
		return fmt.Errorf("proof of possession: issuedAt is too far in the future")
	}

	raw, err := base64.StdEncoding.DecodeString(proof)
	if err != nil {
		return fmt.Errorf("proof of possession: not valid base64: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("proof of possession: signature is %d bytes, want %d",
			len(raw), ed25519.SignatureSize)
	}

	// The key id must match the key material being registered, or a proof
	// over one key could be presented alongside another key's bytes.
	derived, err := KeyID(pub)
	if err != nil {
		return err
	}
	if derived != keyID {
		return fmt.Errorf("%w: registration names %q but the submitted key is %q",
			protocol.ErrKeyIDMismatch, keyID, derived)
	}

	if !ed25519.Verify(pub, ProofInput(tenantID, agentID, keyID, issuedAt), raw) {
		return fmt.Errorf("proof of possession: signature does not verify; "+
			"the registrant does not hold the private key for %s", keyID)
	}

	return nil
}
