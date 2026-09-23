package signer

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"
)

// SeparatedSigner talks to a signing daemon over a unix socket.
//
// The key never enters this process. An attacker who fully owns the gateway
// can ask the daemon to sign things for as long as they hold it -- that much
// is unavoidable for any online signer, including an HSM -- but they cannot
// take the key with them. Eviction actually ends their capability, which is
// not true when the key is a file the gateway can read.
//
// This is also the shape a KMS or PKCS#11 backend takes, so moving to one is
// a change of implementation rather than a change of design.
type SeparatedSigner struct {
	socketPath string
	keyID      string
	pub        ed25519.PublicKey
	timeout    time.Duration

	mu     sync.Mutex
	closed bool
}

// SeparatedConfig configures a separated signer.
type SeparatedConfig struct {
	SocketPath string

	// Timeout bounds a single signing call. The signer sits in the request
	// path, so a wedged daemon must surface as a fast failure rather than as
	// gateway latency.
	Timeout time.Duration
}

// Connect dials the signing daemon and learns which key it holds.
//
// Connecting eagerly means a misconfigured or absent daemon fails at startup
// rather than on the first request that needs a signature.
func Connect(cfg SeparatedConfig) (*SeparatedSigner, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	s := &SeparatedSigner{socketPath: cfg.SocketPath, timeout: timeout}

	resp, err := s.call(Request{Op: OpDescribe})
	if err != nil {
		return nil, fmt.Errorf("%w: signing daemon at %s: %v",
			ErrKeyUnavailable, cfg.SocketPath, err)
	}

	pub, err := decodeB64(resp.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: daemon returned a malformed public key", ErrKeyUnavailable)
	}

	s.keyID = resp.KeyID
	s.pub = ed25519.PublicKey(pub)
	return s, nil
}

func (s *SeparatedSigner) call(req Request) (*Response, error) {
	conn, err := net.DialTimeout("unix", s.socketPath, s.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, err
	}

	if err := writeJSON(json.NewEncoder(conn), req); err != nil {
		return nil, err
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, fmt.Errorf("daemon refused: %s", resp.Error)
	}
	return &resp, nil
}

func (s *SeparatedSigner) KeyID() string { return s.keyID }

func (s *SeparatedSigner) Public() ed25519.PublicKey { return s.pub }

// Sign asks the daemon for a signature.
//
// The result is verified against the public key learned at connect time
// before being returned. Without that check, a daemon that was swapped or
// subverted after startup could hand back arbitrary bytes and the gateway
// would attach them to principal assertions as though they were signatures.
func (s *SeparatedSigner) Sign(message []byte) ([]byte, error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()

	if closed {
		return nil, ErrClosed
	}
	if len(message) > MaxMessageBytes {
		return nil, fmt.Errorf("signer: message is %d bytes, limit is %d",
			len(message), MaxMessageBytes)
	}

	resp, err := s.call(Request{Op: OpSign, Message: encodeB64(message)})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnavailable, err)
	}

	sig, err := decodeB64(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: malformed signature from daemon", ErrKeyUnavailable)
	}

	if !ed25519.Verify(s.pub, message, sig) {
		return nil, fmt.Errorf("%w: daemon returned a signature that does not verify "+
			"against the key it advertised", ErrKeyUnavailable)
	}

	return sig, nil
}

func (s *SeparatedSigner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return nil
}

func (s *SeparatedSigner) Custody() Custody { return CustodySeparated }

func (s *SeparatedSigner) Description() string {
	return fmt.Sprintf("key %s held by the signing daemon at %s -- "+
		"a compromise of this process cannot exfiltrate it", s.keyID, s.socketPath)
}
