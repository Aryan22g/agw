package agentgw

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/Aryan22g/agw/pkg/ags1/httpmsig"
	"github.com/Aryan22g/agw/pkg/ags1/keys"
)

// publicKey aliases ed25519.PublicKey for readability at call sites.
type publicKey = ed25519.PublicKey

// SigningTransport applies an AGS1 signature to every outbound request.
//
// Implementing this as a RoundTripper rather than a bespoke client method is
// what lets an existing library that takes an *http.Client work against the
// gateway with no code change.
type SigningTransport struct {
	Base http.RoundTripper

	TenantID string
	AgentID  string
	KeyID    string

	PrivateKey ed25519.PrivateKey
}

// RoundTrip signs and forwards a request.
//
// Per the RoundTripper contract this must not modify the caller's request, so
// the request is cloned before any header or body is touched.
func (t *SigningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if len(t.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("agentgw: signing transport has no valid private key")
	}

	clone := req.Clone(req.Context())

	var body []byte
	if req.Body != nil && req.Body != http.NoBody {
		// GetBody, when present, gives a repeatable reader; prefer it so a
		// retry or redirect can re-sign the same bytes.
		reader := req.Body
		if req.GetBody != nil {
			fresh, err := req.GetBody()
			if err != nil {
				return nil, fmt.Errorf("agentgw: read request body: %w", err)
			}
			reader = fresh
		}

		read, err := io.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("agentgw: read request body: %w", err)
		}
		_ = reader.Close()
		body = read
	}

	if _, err := httpmsig.Sign(httpmsig.SignInput{
		Request:    clone,
		Body:       body,
		TenantID:   t.TenantID,
		AgentID:    t.AgentID,
		KeyID:      t.KeyID,
		PrivateKey: t.PrivateKey,
	}); err != nil {
		return nil, fmt.Errorf("agentgw: sign request: %w", err)
	}

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}

// normalizePrivateKey accepts either raw Ed25519 key bytes or a base64
// encoding of them.
func normalizePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	if len(raw) == 0 {
		return nil, errors.New("agentgw: private key is required")
	}
	if len(raw) == ed25519.PrivateKeySize {
		return ed25519.PrivateKey(raw), nil
	}

	priv, err := keys.DecodePrivateKey(string(raw))
	if err != nil {
		return nil, fmt.Errorf("agentgw: private key must be %d raw bytes or their base64 encoding: %w",
			ed25519.PrivateKeySize, err)
	}
	return priv, nil
}
