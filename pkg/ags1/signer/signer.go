// Package signer abstracts custody of a private key.
//
// The gateway terminates untrusted network traffic. If its signing key lives
// in its own address space, then a memory disclosure bug, a dependency
// compromise, or a container escape hands an attacker the key itself -- and
// with it the ability to mint principal assertions and forge audit
// checkpoints indefinitely, long after the intrusion is closed.
//
// Every implementation here answers the same question differently: where does
// the key live, and what does an attacker who owns the gateway process
// actually get? A file-backed key gives them the key. A separated or
// KMS-backed key gives them the ability to request signatures while they hold
// the process, and nothing that survives eviction.
package signer

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// Signer produces Ed25519 signatures without necessarily exposing the key.
//
// Deliberately narrow: there is no method to export private key material. An
// implementation that could would defeat the point, and a narrow interface
// means a reviewer can confirm that by reading it.
type Signer interface {
	// KeyID identifies the key, so a verifier can select the right public
	// half. For AGS1 keys this is the RFC 7638 thumbprint.
	KeyID() string

	// Public returns the public half.
	Public() ed25519.PublicKey

	// Sign returns a detached signature over message.
	Sign(message []byte) ([]byte, error)

	// Close releases any resources. Safe to call more than once.
	Close() error
}

// Errors returned by signer implementations.
var (
	// ErrKeyUnavailable means the key could not be reached: a signing daemon
	// is down, a KMS call failed, an HSM session dropped. Callers must treat
	// this as a hard failure, never as permission to proceed unsigned.
	ErrKeyUnavailable = errors.New("signer: key is unavailable")

	// ErrClosed means the signer has been shut down.
	ErrClosed = errors.New("signer: closed")
)

// Custody describes where a signer's key material actually lives.
//
// Reported at startup and in health output so an operator can confirm the
// posture they think they configured. "We use an HSM" is a claim worth being
// able to check at runtime rather than in a deployment doc.
type Custody string

const (
	// CustodyProcess means the key is in this process's memory, loaded from
	// a file. Adequate for development; a compromise of the gateway is a
	// compromise of the key.
	CustodyProcess Custody = "process"

	// CustodySeparated means the key lives in a separate local process. A
	// gateway compromise can request signatures for as long as it holds the
	// process, but cannot exfiltrate the key.
	CustodySeparated Custody = "separated"

	// CustodyExternal means the key never leaves a KMS or HSM. Same
	// containment as separated, plus the key is not on this host at all and
	// its use is logged where the gateway cannot edit it.
	CustodyExternal Custody = "external"
)

// Described is implemented by signers that can report their custody model.
type Described interface {
	Custody() Custody
	Description() string
}

// CustodyOf reports a signer's custody model, defaulting to the weakest
// assumption when the signer does not say. Guessing generously about a
// security posture is how a deployment ends up believing it has protections
// it does not.
func CustodyOf(s Signer) Custody {
	if d, ok := s.(Described); ok {
		return d.Custody()
	}
	return CustodyProcess
}

// DescriptionOf renders a human-readable custody line for logs and health.
func DescriptionOf(s Signer) string {
	if d, ok := s.(Described); ok {
		return d.Description()
	}
	return fmt.Sprintf("key %s held in process memory", s.KeyID())
}
