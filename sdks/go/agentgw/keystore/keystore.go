// Package keystore persists AGS1 agent keys on local disk.
package keystore

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
)

// Record is one stored agent identity.
type Record struct {
	TenantID   string    `json:"tenantId"`
	AgentID    string    `json:"agentId"`
	KeyID      string    `json:"keyId"`
	PrivateKey string    `json:"privateKey"`
	PublicKey  string    `json:"publicKey"`
	CreatedAt  time.Time `json:"createdAt"`
	GatewayURL string    `json:"gatewayUrl,omitempty"`
}

// ErrNotFound is returned when no key file exists at the given path.
var ErrNotFound = errors.New("keystore: no key found")

// FileStore reads and writes a single key file.
//
// The file holds an unencrypted private key, so its permissions are the only
// thing protecting it. Load refuses to read a file that is group- or
// world-readable rather than warning: a key that has already been exposed to
// other local users should be rotated, not used.
type FileStore struct {
	path string
}

// NewFileStore builds a store over a path. An empty path resolves to
// ~/.ags/credentials.json.
func NewFileStore(path string) (*FileStore, error) {
	if strings.TrimSpace(path) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("keystore: resolve home dir: %w", err)
		}
		path = filepath.Join(home, ".ags", "credentials.json")
	}
	return &FileStore{path: filepath.Clean(path)}, nil
}

// Path returns the file this store reads and writes.
func (s *FileStore) Path() string { return s.path }

// Save writes a record with 0600 permissions.
//
// The write goes to a temporary file in the same directory and is then
// renamed, so an interrupted write cannot leave a truncated key file behind.
func (s *FileStore) Save(rec Record) error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("keystore: create dir: %w", err)
	}

	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return fmt.Errorf("keystore: encode record: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".credentials-*.tmp")
	if err != nil {
		return fmt.Errorf("keystore: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("keystore: chmod temp file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("keystore: write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("keystore: sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("keystore: close temp file: %w", err)
	}

	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("keystore: install key file: %w", err)
	}
	return nil
}

// Load reads a record, refusing files with unsafe permissions.
func (s *FileStore) Load() (*Record, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w at %s", ErrNotFound, s.path)
		}
		return nil, fmt.Errorf("keystore: stat: %w", err)
	}

	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf(
			"keystore: %s is readable by other users (mode %04o); "+
				"run 'chmod 600 %s' and rotate this key, since it may already be compromised",
			s.path, perm, s.path)
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("keystore: read: %w", err)
	}

	var rec Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("keystore: parse: %w", err)
	}

	// The stored kid must still match the stored key material, so a hand
	// edited file cannot point the SDK at a credential it does not hold the
	// key for.
	priv, err := keys.DecodePrivateKey(rec.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("keystore: %w", err)
	}
	derived, err := keys.KeyID(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("keystore: derive key id: %w", err)
	}
	if rec.KeyID != "" && rec.KeyID != derived {
		return nil, fmt.Errorf("keystore: stored key id %q does not match the stored key material (%q)",
			rec.KeyID, derived)
	}
	rec.KeyID = derived

	return &rec, nil
}
