package signer

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
)

// FileSigner holds the key in this process's memory, loaded from disk.
//
// The weakest custody model, and the honest default for development. A
// compromise of the gateway is a compromise of the key, and the key survives
// the intrusion: an attacker who reads it once can mint assertions and forge
// audit checkpoints forever after, with nothing in the system able to tell.
// Production deployments should use a separated or external signer.
type FileSigner struct {
	keyID string
	path  string

	mu     sync.RWMutex
	priv   ed25519.PrivateKey
	closed bool
}

// FromFile loads a base64 Ed25519 private key from disk.
func FromFile(path, keyID string) (*FileSigner, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: read %s: %v", ErrKeyUnavailable, path, err)
	}

	priv, err := keys.DecodePrivateKey(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("signer: decode %s: %w", path, err)
	}

	// Refuse a key file other local users can read. A key already exposed to
	// another account should be rotated, not loaded.
	if info, err := os.Stat(path); err == nil {
		if perm := info.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf(
				"signer: %s is readable by other users (mode %04o); "+
					"run 'chmod 600 %s' and rotate this key", path, perm, path)
		}
	}

	if keyID == "" {
		derived, err := keys.KeyID(priv.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}
		keyID = derived
	}

	return &FileSigner{keyID: keyID, path: path, priv: priv}, nil
}

// FromKey wraps an in-memory key, for tests and embedded use.
func FromKey(priv ed25519.PrivateKey, keyID string) (*FileSigner, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("signer: private key is %d bytes, want %d",
			len(priv), ed25519.PrivateKeySize)
	}
	if keyID == "" {
		derived, err := keys.KeyID(priv.Public().(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}
		keyID = derived
	}
	return &FileSigner{keyID: keyID, priv: priv}, nil
}

func (s *FileSigner) KeyID() string { return s.keyID }

func (s *FileSigner) Public() ed25519.PublicKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.priv == nil {
		return nil
	}
	return s.priv.Public().(ed25519.PublicKey)
}

func (s *FileSigner) Sign(message []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed || s.priv == nil {
		return nil, ErrClosed
	}
	return ed25519.Sign(s.priv, message), nil
}

// Close zeroes the key material.
//
// Best-effort: Go may have copied it during earlier allocation, so this
// narrows the window a heap dump would catch it in rather than closing it.
func (s *FileSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.priv {
		s.priv[i] = 0
	}
	s.priv = nil
	s.closed = true
	return nil
}

func (s *FileSigner) Custody() Custody { return CustodyProcess }

func (s *FileSigner) Description() string {
	where := s.path
	if where == "" {
		where = "supplied in memory"
	}
	return fmt.Sprintf("key %s held in process memory (%s) -- "+
		"a compromise of this process exposes the key", s.keyID, where)
}
