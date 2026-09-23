package signer

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Daemon holds a private key and signs on request over a unix socket.
//
// It exists to be small. Everything the gateway needs is two operations, and
// deliberately nothing else: no key export, no key generation, no
// configuration surface. If the gateway is compromised, this process is what
// stands between the attacker and a key they can keep, so its attack surface
// should be short enough to read in full.
type Daemon struct {
	signer   Signer
	listener net.Listener
	logger   *slog.Logger

	// signCount is exported through Stats so an operator can compare
	// signature volume against request volume. A daemon signing far more than
	// the gateway is serving is what a compromised gateway harvesting
	// signatures looks like.
	mu        sync.Mutex
	signCount uint64
	closed    bool

	// Per-purpose accounting. A daemon that suddenly signs ten thousand
	// principal assertions a minute is what a compromised gateway harvesting
	// signatures looks like, and it is invisible in a single total.
	byPurpose map[string]uint64
	refused   map[string]uint64
	buckets   map[string]*tokenBucket

	allowed map[string]bool
}

// tokenBucket is a plain rate limiter. A signing daemon has no reason to
// serve bursts of thousands, and the limit turns a silent harvest into a
// visible failure.
type tokenBucket struct {
	capacity float64
	perSec   float64
	tokens   float64
	last     time.Time
}

func newTokenBucket(perSec float64, capacity float64) *tokenBucket {
	return &tokenBucket{capacity: capacity, perSec: perSec, tokens: capacity, last: time.Now()}
}

// take must be called with the daemon's mutex held.
func (b *tokenBucket) take(now time.Time) bool {
	elapsed := now.Sub(b.last).Seconds()
	b.last = now
	b.tokens += elapsed * b.perSec
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// DaemonConfig configures the signing daemon.
type DaemonConfig struct {
	// SocketPath is created with 0600 permissions. Unix socket permissions
	// are the access control here: anything that can connect can request
	// signatures.
	SocketPath string

	Signer Signer
	Logger *slog.Logger

	// Purposes the daemon will sign for. Empty means both known purposes.
	//
	// A deployment where one daemon holds the checkpoint key and another
	// holds the assertion key should name exactly one here, so that
	// compromising the gateway cannot produce checkpoints even if it can
	// reach both sockets.
	Purposes []string

	// SignsPerSecond and Burst bound each purpose independently. Zero
	// selects defaults that are far above real traffic and far below a
	// harvest.
	SignsPerSecond float64
	Burst          float64
}

// NewDaemon starts a signing daemon.
func NewDaemon(cfg DaemonConfig) (*Daemon, error) {
	if cfg.Signer == nil {
		return nil, errors.New("signing daemon: a signer is required")
	}
	if cfg.SocketPath == "" {
		return nil, errors.New("signing daemon: socket path is required")
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	if err := os.MkdirAll(filepath.Dir(cfg.SocketPath), 0o700); err != nil {
		return nil, fmt.Errorf("signing daemon: create socket dir: %w", err)
	}
	// A stale socket from an unclean shutdown would otherwise block binding.
	_ = os.Remove(cfg.SocketPath)

	ln, err := net.Listen("unix", cfg.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("signing daemon: listen: %w", err)
	}
	if err := os.Chmod(cfg.SocketPath, 0o600); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("signing daemon: restrict socket: %w", err)
	}

	purposes := cfg.Purposes
	if len(purposes) == 0 {
		purposes = []string{PurposePrincipalContext, PurposeEvidenceCheckpoint, PurposeReadinessProbe}
	}
	allowed := make(map[string]bool, len(purposes))
	for _, p := range purposes {
		switch p {
		case PurposePrincipalContext, PurposeEvidenceCheckpoint, PurposeReadinessProbe:
			allowed[p] = true
		default:
			_ = ln.Close()
			return nil, fmt.Errorf("signing daemon: unknown purpose %q", p)
		}
	}

	rate := cfg.SignsPerSecond
	if rate <= 0 {
		rate = 2000
	}
	burst := cfg.Burst
	if burst <= 0 {
		burst = 4000
	}

	buckets := make(map[string]*tokenBucket, len(allowed))
	for p := range allowed {
		buckets[p] = newTokenBucket(rate, burst)
	}

	return &Daemon{
		signer:    cfg.Signer,
		listener:  ln,
		logger:    logger,
		allowed:   allowed,
		buckets:   buckets,
		byPurpose: make(map[string]uint64, len(allowed)),
		refused:   make(map[string]uint64),
	}, nil
}

// authorizeSigning decides whether a message may be signed, and accounts for
// it. The purpose is derived from the message's own bytes, never from what the
// caller claims.
func (d *Daemon) authorizeSigning(declared string, message []byte) (purpose string, err error) {
	purpose, err = ClassifyPurpose(message)
	if err != nil {
		d.countRefusal("unknown")
		return "", err
	}
	if declared != "" && declared != purpose {
		d.countRefusal(purpose)
		return "", fmt.Errorf("%w: caller said %q, bytes say %q", ErrPurposeMismatch, declared, purpose)
	}
	if !d.allowed[purpose] {
		d.countRefusal(purpose)
		return "", fmt.Errorf("%w: %s", ErrUnknownPurpose, purpose)
	}
	if err := ValidateForPurpose(purpose, message); err != nil {
		d.countRefusal(purpose)
		return "", err
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if b := d.buckets[purpose]; b != nil && !b.take(time.Now()) {
		d.refused[purpose]++
		return "", fmt.Errorf("%w: %s", ErrRateLimited, purpose)
	}
	return purpose, nil
}

func (d *Daemon) countRefusal(purpose string) {
	d.mu.Lock()
	d.refused[purpose]++
	d.mu.Unlock()
}

// Serve accepts connections until Close.
func (d *Daemon) Serve() error {
	for {
		conn, err := d.listener.Accept()
		if err != nil {
			d.mu.Lock()
			closed := d.closed
			d.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go d.handle(conn)
	}
}

func (d *Daemon) handle(conn net.Conn) {
	defer conn.Close()

	// A caller that connects and stalls must not hold a goroutine open.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Bound what a single connection can make the daemon read.
	dec := json.NewDecoder(io.LimitReader(conn, MaxMessageBytes*2))
	enc := json.NewEncoder(conn)

	var req Request
	if err := dec.Decode(&req); err != nil {
		_ = writeJSON(enc, Response{Error: "malformed request"})
		return
	}

	switch req.Op {
	case OpDescribe:
		_ = writeJSON(enc, Response{
			OK:        true,
			KeyID:     d.signer.KeyID(),
			PublicKey: encodeB64(d.signer.Public()),
		})

	case OpSign:
		message, err := decodeB64(req.Message)
		if err != nil {
			_ = writeJSON(enc, Response{Error: "message is not valid base64"})
			return
		}
		if len(message) == 0 || len(message) > MaxMessageBytes {
			_ = writeJSON(enc, Response{Error: "message length out of range"})
			return
		}

		// Nothing is signed until the bytes themselves declare a purpose this
		// daemon serves and parse as that purpose's canonical form.
		purpose, err := d.authorizeSigning(req.Purpose, message)
		if err != nil {
			d.logger.Warn("refused to sign",
				slog.String("declared_purpose", req.Purpose),
				slog.Int("message_bytes", len(message)),
				slog.Any("error", err))
			// The caller learns it was refused, not which check refused it.
			_ = writeJSON(enc, Response{Error: "refused: message is not a signable purpose"})
			return
		}

		sig, err := d.signer.Sign(message)
		if err != nil {
			// The reason is logged locally but not returned: the caller
			// learns the operation failed, not anything about the key.
			d.logger.Error("signing failed", slog.Any("error", err))
			_ = writeJSON(enc, Response{Error: "signing failed"})
			return
		}

		d.mu.Lock()
		d.signCount++
		d.byPurpose[purpose]++
		d.mu.Unlock()

		_ = writeJSON(enc, Response{OK: true, Signature: encodeB64(sig)})

	default:
		_ = writeJSON(enc, Response{Error: "unsupported operation"})
	}
}

// Stats reports how many signatures the daemon has produced.
func (d *Daemon) Stats() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.signCount
}

// PurposeStats reports signatures issued and requests refused, per purpose.
//
// The refusal counts are the operational signal worth alerting on. A daemon
// refusing messages it does not recognise is a daemon being asked to sign
// something it was never meant to, and in a healthy deployment that number
// stays at zero.
func (d *Daemon) PurposeStats() (signed, refused map[string]uint64) {
	d.mu.Lock()
	defer d.mu.Unlock()

	signed = make(map[string]uint64, len(d.byPurpose))
	for k, v := range d.byPurpose {
		signed[k] = v
	}
	refused = make(map[string]uint64, len(d.refused))
	for k, v := range d.refused {
		refused[k] = v
	}
	return signed, refused
}

// Close stops the daemon and removes its socket.
func (d *Daemon) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()

	err := d.listener.Close()
	_ = d.signer.Close()
	return err
}

// PublicKey exposes the held key's public half, for tooling.
func (d *Daemon) PublicKey() ed25519.PublicKey { return d.signer.Public() }
