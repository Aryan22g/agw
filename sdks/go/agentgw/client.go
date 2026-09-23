// Package agentgw is the Go SDK for calling resources through the Agent
// Gateway.
//
// The whole point of the SDK is that an agent developer never has to think
// about canonicalization, digests, nonces or signature bases. They construct
// a Client once and then use it like an *http.Client:
//
//	client, err := agentgw.New(agentgw.Config{
//	    GatewayURL: "https://gw.example.com",
//	    TenantID:   "tenant-alpha",
//	    AgentID:    "agent-support",
//	    PrivateKey: priv,
//	})
//	resp, err := client.PostJSON(ctx, "/v1/tools/github/repos/acme/app/issues", payload)
//
// Signing is applied by a RoundTripper, so anything that accepts an
// *http.Client can be pointed at the gateway without further change.
package agentgw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
)

// Config configures a Client.
type Config struct {
	// GatewayURL is the base URL of the gateway, e.g. https://gw.example.com
	GatewayURL string

	TenantID string
	AgentID  string

	// PrivateKey is the agent's Ed25519 signing key.
	PrivateKey []byte

	// KeyID is derived from PrivateKey when empty.
	KeyID string

	// Timeout bounds each request. Defaults to 30s.
	Timeout time.Duration

	// Transport is the underlying RoundTripper. Defaults to
	// http.DefaultTransport.
	Transport http.RoundTripper
}

// Client is a signing HTTP client aimed at one gateway.
type Client struct {
	http    *http.Client
	baseURL *url.URL
	keyID   string
}

// New builds a Client.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.GatewayURL) == "" {
		return nil, errors.New("agentgw: gateway url is required")
	}
	base, err := url.Parse(strings.TrimRight(cfg.GatewayURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("agentgw: invalid gateway url: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("agentgw: gateway url %q must be absolute", cfg.GatewayURL)
	}
	// A signature proves who sent a request; it does not keep the body
	// private. Refusing plaintext by default stops an agent from shipping
	// payloads in the clear without having made that choice deliberately.
	if base.Scheme != "https" && !isLoopback(base.Hostname()) {
		return nil, fmt.Errorf("agentgw: gateway url must use https (got %q); "+
			"plain http is permitted only for loopback during development", base.Scheme)
	}

	if strings.TrimSpace(cfg.TenantID) == "" || strings.TrimSpace(cfg.AgentID) == "" {
		return nil, errors.New("agentgw: tenant id and agent id are required")
	}

	priv, err := normalizePrivateKey(cfg.PrivateKey)
	if err != nil {
		return nil, err
	}

	keyID := cfg.KeyID
	if keyID == "" {
		derived, err := keys.KeyID(priv.Public().(publicKey))
		if err != nil {
			return nil, fmt.Errorf("agentgw: derive key id: %w", err)
		}
		keyID = derived
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	base_rt := cfg.Transport
	if base_rt == nil {
		base_rt = http.DefaultTransport
	}

	return &Client{
		baseURL: base,
		keyID:   keyID,
		http: &http.Client{
			Timeout: timeout,
			Transport: &SigningTransport{
				Base:       base_rt,
				TenantID:   cfg.TenantID,
				AgentID:    cfg.AgentID,
				KeyID:      keyID,
				PrivateKey: priv,
			},
		},
	}, nil
}

// KeyID returns the credential identifier this client signs with.
func (c *Client) KeyID() string { return c.keyID }

// HTTPClient exposes the underlying signing client, so an existing library
// that accepts an *http.Client can be pointed at the gateway unchanged.
func (c *Client) HTTPClient() *http.Client { return c.http }

// Do sends an already-built request. A relative URL is resolved against the
// gateway base URL.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if !req.URL.IsAbs() {
		req.URL = c.baseURL.ResolveReference(req.URL)
	}
	return c.http.Do(req)
}

// PostJSON sends a JSON body and decodes nothing; the caller owns the
// response.
//
// The body is marshalled here and handed to the signer, which canonicalizes
// it with JCS and replaces the request body with those exact bytes. That is
// what keeps the digest and the transmitted bytes in agreement.
func (c *Client) PostJSON(ctx context.Context, path string, payload any) (*http.Response, error) {
	return c.sendJSON(ctx, http.MethodPost, path, payload)
}

// PutJSON sends a JSON body with PUT.
func (c *Client) PutJSON(ctx context.Context, path string, payload any) (*http.Response, error) {
	return c.sendJSON(ctx, http.MethodPut, path, payload)
}

// Get sends a body-less GET.
func (c *Client) Get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.resolve(path), nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

// Delete sends a body-less DELETE.
func (c *Client) Delete(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.resolve(path), nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func (c *Client) sendJSON(ctx context.Context, method, path string, payload any) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("agentgw: encode body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.resolve(path), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	return c.http.Do(req)
}

func (c *Client) resolve(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return c.baseURL.String() + path
}

// DecodeJSON reads a JSON response body, turning a gateway denial into a
// typed *Error so callers can branch on the reason code rather than the
// status alone.
func DecodeJSON(resp *http.Response, out any) error {
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return parseError(resp)
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func isLoopback(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
