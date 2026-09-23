package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gwaudit "github.com/Aryan22g/agw/internal/gateway/audit"
	"github.com/Aryan22g/agw/pkg/ags1/keys"
	"github.com/Aryan22g/agw/pkg/ags1/signer"
)

// checkpointKey is the resolved custody of the key that signs evidence
// checkpoints.
type checkpointKey struct {
	signer gwaudit.CheckpointSigner
	keyID  string

	// PubPath is where the public half lives, when there is a file for it.
	// It is what the user needs to verify, so every command prints it.
	PubPath string

	// Source describes where the key came from, for the startup banner.
	Source string

	close func()
}

// agwHome is where agw keeps state that belongs to the operator rather than
// to one run: today, the default checkpoint key.
func agwHome() (string, error) {
	if h := strings.TrimSpace(os.Getenv("AGW_HOME")); h != "" {
		return h, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot find a home directory for the default checkpoint key; set AGW_HOME: %w", err)
	}
	return filepath.Join(home, ".agw"), nil
}

// resolveCheckpointKey decides which key signs this run's checkpoints.
//
// The flag value may be:
//
//	""               $AGW_CHECKPOINT_KEY, else $AGW_HOME/checkpoint.key,
//	                 generated on first use
//	PATH             a key file written by `agw keygen`
//	unix:PATH        a running ags-signd, so the key never enters this process
//	none             no signatures (the chain detects edits but cannot be pinned)
//
// Defaulting to a generated key rather than to none is the important choice.
// An unsigned chain is internally consistent and proves nothing against
// anyone who can rewrite the file, and the verifier now says exactly that.
// The five-minute path therefore has to produce signed evidence without being
// asked, or the first thing a new user sees is a verification failure.
//
// A key kept on the same machine as the evidence is weaker custody than a
// separate daemon or KMS. It is still strictly better than no key, and
// `unix:` is one flag away when the deployment warrants it.
func resolveCheckpointKey(flagVal string) (*checkpointKey, error) {
	v := strings.TrimSpace(flagVal)
	if v == "" {
		v = strings.TrimSpace(os.Getenv("AGW_CHECKPOINT_KEY"))
	}

	switch {
	case strings.EqualFold(v, "none"):
		return &checkpointKey{Source: "none (unsigned: edits are detectable, a full rewrite is not)",
			close: func() {}}, nil

	case strings.HasPrefix(v, "unix:"):
		sock := strings.TrimPrefix(strings.TrimPrefix(v, "unix:"), "//")
		s, err := signer.Connect(signer.SeparatedConfig{SocketPath: sock})
		if err != nil {
			return nil, fmt.Errorf("checkpoint signer: %w", err)
		}
		// The daemon knows its public key; write nothing, but say where the
		// verifier can get it.
		return &checkpointKey{
			signer: s, keyID: s.KeyID(),
			Source: "ags-signd at " + sock + " (separate custody)",
			close:  func() { _ = s.Close() },
		}, nil

	case v != "":
		s, err := signer.FromFile(v, "")
		if err != nil {
			return nil, err
		}
		return &checkpointKey{
			signer: s, keyID: s.KeyID(), PubPath: pubPathFor(v),
			Source: "key file " + v, close: func() { _ = s.Close() },
		}, nil
	}

	home, err := agwHome()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(home, "checkpoint.key")
	source := "default key " + path

	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(home, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", home, err)
		}
		if _, err := writeKeypair(path, path+".pub"); err != nil {
			return nil, err
		}
		source = "default key " + path + " (generated just now)"
	}

	s, err := signer.FromFile(path, "")
	if err != nil {
		return nil, err
	}
	return &checkpointKey{
		signer: s, keyID: s.KeyID(), PubPath: pubPathFor(path),
		Source: source, close: func() { _ = s.Close() },
	}, nil
}

// apply puts the key into an evidence sink configuration.
func (k *checkpointKey) apply(cfg *gwaudit.EvidenceSinkConfig) {
	if k.signer != nil {
		cfg.Signer = k.signer
		cfg.KeyID = k.keyID
	}
}

// Close releases the signer.
func (k *checkpointKey) Close() {
	if k.close != nil {
		k.close()
	}
}

// verifyHint is the exact command a user runs to check what was produced.
func (k *checkpointKey) verifyHint(evidence string) string {
	switch {
	case k.signer == nil:
		return fmt.Sprintf("agw audit verify %s", evidence)
	case k.PubPath != "":
		return fmt.Sprintf("agw audit verify %s --key %s", evidence, k.PubPath)
	default:
		pub := base64.StdEncoding.EncodeToString(signerPublic(k.signer))
		return fmt.Sprintf("agw audit verify %s --key %s", evidence, pub)
	}
}

func signerPublic(s gwaudit.CheckpointSigner) []byte {
	if p, ok := s.(interface{ Public() ed25519.PublicKey }); ok {
		return p.Public()
	}
	return nil
}

// pubPathFor returns the public key file that sits next to a private key, if
// it exists. `agw keygen` writes KEY.pub by default.
func pubPathFor(keyPath string) string {
	p := keyPath + ".pub"
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

// writeKeypair writes an Ed25519 checkpoint keypair in the format the signer
// reads, and returns the key id.
func writeKeypair(privPath, pubPath string) (string, error) {
	kp, err := keys.Generate()
	if err != nil {
		return "", err
	}
	// O_EXCL: never overwrite a key. Replacing a checkpoint key silently
	// would orphan every chain it signed.
	f, err := os.OpenFile(privPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(kp.PrivateKey)); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(kp.PublicKey)+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}
	return kp.KeyID, nil
}

// agwCheckpointInterval is how long a record can sit unsigned in a quiet log.
//
// Records after the last checkpoint are the ones that can be removed without
// detection, so for a long-running enforcement point this is the size of
// that window. Ten seconds costs one signature and one fsync per interval,
// and only when there is something new to sign.
const agwCheckpointInterval = 10 * time.Second
