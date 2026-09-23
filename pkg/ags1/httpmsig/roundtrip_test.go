package httpmsig_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/canonicalhttp"
	"github.com/Aryan22g/agw/pkg/ags1/httpmsig"
	"github.com/Aryan22g/agw/pkg/ags1/keys"
	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

// signAndReceive signs a client-side request, then replays it through
// httptest so verification runs against a genuine server-side *http.Request.
//
// The round trip is the point: a signer and verifier that only ever meet
// in-process can agree on bytes the network would never produce.
func signAndReceive(t *testing.T, method, target string, body []byte, contentType string) (*canonicalhttp.CanonicalRequest, *http.Request, *keys.KeyPair, *httpmsig.SignResult) {
	t.Helper()

	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	res, err := httpmsig.Sign(httpmsig.SignInput{
		Request:    req,
		Body:       body,
		TenantID:   "tenant-alpha",
		AgentID:    "agent-support-01",
		PrivateKey: kp.PrivateKey,
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Replay the signed request through a real server to pick up
	// server-side URL and Host parsing.
	rec := httptest.NewRequest(method, target, bytes.NewReader(res.Body))
	rec.Header = req.Header.Clone()
	rec.Host = req.Host
	if rec.Host == "" {
		rec.Host = req.URL.Host
	}

	received, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	canon, err := canonicalhttp.FromHTTPRequest(rec, received)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}

	return canon, rec, kp, res
}

func TestSignVerifyRoundTripWithBody(t *testing.T) {
	body := []byte(`{"repo":"acme/app","title":"Bug report","labels":["p1","triage"]}`)
	canon, req, kp, res := signAndReceive(t, http.MethodPost,
		"https://gw.example.com/v1/tools/github/repos/acme/app/issues?dry_run=false", body, "application/json")

	out, err := httpmsig.Verify(httpmsig.VerifyInput{
		Request:              canon,
		SignatureInputHeader: req.Header.Get("Signature-Input"),
		SignatureHeader:      req.Header.Get("Signature"),
		PublicKey:            kp.PublicKey,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if out.KeyID != kp.KeyID {
		t.Errorf("keyid = %q, want %q", out.KeyID, kp.KeyID)
	}
	if len(out.Components) != 11 {
		t.Errorf("covered components = %d, want 11 for a body-bearing request", len(out.Components))
	}
	if !bytes.Equal(out.SignatureBase, res.SignatureBase) {
		t.Errorf("signature base differs between signer and verifier:\nsigner:\n%s\nverifier:\n%s",
			res.SignatureBase, out.SignatureBase)
	}
}

func TestSignVerifyRoundTripWithoutBody(t *testing.T) {
	canon, req, kp, _ := signAndReceive(t, http.MethodGet,
		"https://gw.example.com/v1/tools/github/repos/acme/app/issues", nil, "")

	out, err := httpmsig.Verify(httpmsig.VerifyInput{
		Request:              canon,
		SignatureInputHeader: req.Header.Get("Signature-Input"),
		SignatureHeader:      req.Header.Get("Signature"),
		PublicKey:            kp.PublicKey,
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	if len(out.Components) != 9 {
		t.Errorf("covered components = %d, want 9 for a body-less request", len(out.Components))
	}
}

// TestTamperRejected is the core security property: any mutation to a covered
// component after signing must break verification.
func TestTamperRejected(t *testing.T) {
	body := []byte(`{"amount":100}`)

	tests := []struct {
		name    string
		mutate  func(canon *canonicalhttp.CanonicalRequest, req *http.Request)
		wantErr error
	}{
		{
			name: "body",
			mutate: func(c *canonicalhttp.CanonicalRequest, _ *http.Request) {
				c.Body = []byte(`{"amount":100000}`)
			},
			wantErr: protocol.ErrContentDigestMismatch,
		},
		{
			name: "method",
			mutate: func(c *canonicalhttp.CanonicalRequest, _ *http.Request) {
				c.Method = "DELETE"
			},
			wantErr: protocol.ErrSignatureInvalid,
		},
		{
			name: "path",
			mutate: func(c *canonicalhttp.CanonicalRequest, _ *http.Request) {
				c.Path = "/v1/tools/github/repos/attacker/app/issues"
			},
			wantErr: protocol.ErrSignatureInvalid,
		},
		{
			name: "query",
			mutate: func(c *canonicalhttp.CanonicalRequest, _ *http.Request) {
				c.Query = "?dry_run=true"
			},
			wantErr: protocol.ErrSignatureInvalid,
		},
		{
			name: "authority",
			mutate: func(c *canonicalhttp.CanonicalRequest, _ *http.Request) {
				c.Authority = "evil.example.com"
			},
			wantErr: protocol.ErrSignatureInvalid,
		},
		{
			name: "tenant header",
			mutate: func(c *canonicalhttp.CanonicalRequest, _ *http.Request) {
				c.Headers[protocol.HeaderTenantID] = "tenant-victim"
			},
			wantErr: protocol.ErrSignatureInvalid,
		},
		{
			name: "agent header",
			mutate: func(c *canonicalhttp.CanonicalRequest, _ *http.Request) {
				c.Headers[protocol.HeaderAgentID] = "agent-admin"
			},
			wantErr: protocol.ErrSignatureInvalid,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			canon, req, kp, _ := signAndReceive(t, http.MethodPost,
				"https://gw.example.com/v1/tools/github/repos/acme/app/issues?dry_run=false",
				body, "application/json")

			tc.mutate(canon, req)

			_, err := httpmsig.Verify(httpmsig.VerifyInput{
				Request:              canon,
				SignatureInputHeader: req.Header.Get("Signature-Input"),
				SignatureHeader:      req.Header.Get("Signature"),
				PublicKey:            kp.PublicKey,
			})
			if err == nil {
				t.Fatalf("tampering with %s was accepted", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("got error %v, want one matching %v", err, tc.wantErr)
			}
		})
	}
}

func errorMatches(got, want error) bool { // nolint: retained for wrapped-sentinel checks
	return errors.Is(got, want)
}

func TestWrongKeyRejected(t *testing.T) {
	body := []byte(`{"ok":true}`)
	canon, req, _, _ := signAndReceive(t, http.MethodPost,
		"https://gw.example.com/v1/tools/github/repos/acme/app/issues", body, "application/json")

	attacker, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if _, err := httpmsig.Verify(httpmsig.VerifyInput{
		Request:              canon,
		SignatureInputHeader: req.Header.Get("Signature-Input"),
		SignatureHeader:      req.Header.Get("Signature"),
		PublicKey:            attacker.PublicKey,
	}); err == nil {
		t.Fatal("signature verified against an unrelated public key")
	}
}

func TestExpiredAndFutureRejected(t *testing.T) {
	body := []byte(`{"ok":true}`)
	canon, req, kp, _ := signAndReceive(t, http.MethodPost,
		"https://gw.example.com/v1/tools/github/repos/acme/app/issues", body, "application/json")

	base := httpmsig.VerifyInput{
		Request:              canon,
		SignatureInputHeader: req.Header.Get("Signature-Input"),
		SignatureHeader:      req.Header.Get("Signature"),
		PublicKey:            kp.PublicKey,
	}

	stale := base
	stale.Now = time.Now().UTC().Add(protocol.MaxRequestAgeSeconds*time.Second + time.Minute)
	if _, err := httpmsig.Verify(stale); err == nil {
		t.Error("a request past the age window was accepted")
	}

	early := base
	early.Now = time.Now().UTC().Add(-(protocol.MaxClockSkewSeconds*time.Second + time.Minute))
	if _, err := httpmsig.Verify(early); err == nil {
		t.Error("a request beyond the future skew allowance was accepted")
	}
}

// TestAlgOnWireRejected guards the downgrade defence: AGS1 forbids `alg` in
// Signature-Input so a caller cannot nominate the algorithm.
func TestAlgOnWireRejected(t *testing.T) {
	_, err := httpmsig.ParseSignatureInput(
		`sig1=("@method" "@authority" "@path" "@query" "x-agent-id" "x-tenant-id" "x-request-id" "x-agent-signature-version" "traceparent");created=1710000000;keyid="k";nonce="0123456789012345678901";tag="agw-sig-v1";alg="ed25519"`)
	if err == nil {
		t.Fatal("alg parameter was accepted")
	}
	if !errorMatches(err, protocol.ErrAlgorithmNotOnTheWire) {
		t.Errorf("got %v, want ErrAlgorithmNotOnTheWire", err)
	}
}

// TestTruncatedComponentListRejected guards against a signer shrinking what
// the signature actually covers.
func TestTruncatedComponentListRejected(t *testing.T) {
	_, err := httpmsig.ParseSignatureInput(
		`sig1=("@method" "@path");created=1710000000;keyid="k";nonce="0123456789012345678901";tag="agw-sig-v1"`)
	if err != nil {
		t.Fatalf("parse should succeed; profile check happens at verify: %v", err)
	}

	err = canonicalhttp.ValidateCoveredComponents([]string{"@method", "@path"}, false)
	if err == nil {
		t.Fatal("a truncated component list passed profile validation")
	}
	if !errorMatches(err, protocol.ErrComponentSetMismatch) {
		t.Errorf("got %v, want ErrComponentSetMismatch", err)
	}
}

func TestWrongTagRejected(t *testing.T) {
	_, err := httpmsig.ParseSignatureInput(
		`sig1=("@method" "@authority" "@path" "@query" "x-agent-id" "x-tenant-id" "x-request-id" "x-agent-signature-version" "traceparent");created=1710000000;keyid="k";nonce="0123456789012345678901";tag="some-other-profile"`)
	if err == nil {
		t.Fatal("a foreign profile tag was accepted")
	}
	if !errorMatches(err, protocol.ErrInvalidTag) {
		t.Errorf("got %v, want ErrInvalidTag", err)
	}
}
