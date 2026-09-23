// Command gen produces the AGS1 conformance corpus.
//
// Run with: go run ./pkg/ags1/vectors/gen -out pkg/ags1/vectors/ags1-v1.json
//
// Key material and every other input is fixed, so the output is byte-stable
// across runs. A diff in the generated file therefore means the profile
// changed, which is exactly the signal this is meant to give.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/digest"
	"github.com/Aryan22g/agw/pkg/ags1/httpmsig"
	"github.com/Aryan22g/agw/pkg/ags1/jcs"
	"github.com/Aryan22g/agw/pkg/ags1/keys"
	"github.com/Aryan22g/agw/pkg/ags1/protocol"
	"github.com/Aryan22g/agw/pkg/ags1/vectors"
)

// A fixed seed makes the corpus reproducible. This key is published in the
// repository and is for conformance testing only; it must never be registered
// as a real credential.
var seed = []byte{
	0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
	0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
	0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
	0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
}

const (
	fixedCreated   = int64(1750000000) // 2025-06-15T14:26:40Z
	fixedNonce     = "sT9nUq2vXmK4pLzR8bYwCd"
	fixedRequestID = "req-0000000000000001"
	fixedTrace     = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	tenantID       = "tenant-conformance"
	agentID        = "agent-conformance"
)

func main() {
	out := flag.String("out", "pkg/ags1/vectors/ags1-v1.json", "output path")
	flag.Parse()

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	keyID, err := keys.KeyID(pub)
	if err != nil {
		fatal(err)
	}

	corpus := vectors.Corpus{
		Profile: protocol.ProfileName,
		Version: protocol.SignatureVersion,
		Tag:     protocol.SignatureTag,
	}

	type spec struct {
		name, desc, method, url, body, ctype string
	}

	specs := []spec{
		{
			name: "get-no-query", desc: "Body-less GET; absent query signs as \"?\"",
			method: http.MethodGet, url: "https://gw.example.com/v1/tools/github/repos/acme/app/issues",
		},
		{
			name: "get-with-query", desc: "Body-less GET; query keeps its leading \"?\" and its original order",
			method: http.MethodGet, url: "https://gw.example.com/v1/tools/github/repos/acme/app/issues?state=open&sort=created",
		},
		{
			name: "post-json", desc: "Body-bearing POST; JSON body canonicalized with JCS before digesting",
			method: http.MethodPost, url: "https://gw.example.com/v1/tools/github/repos/acme/app/issues",
			body: `{"title":"Conformance","labels":["p1","triage"],"assignee":null}`, ctype: "application/json",
		},
		{
			name: "post-json-unordered-keys", desc: "JCS reorders object keys, so the transmitted bytes differ from the input",
			method: http.MethodPost, url: "https://gw.example.com/v1/tools/github/repos/acme/app/issues",
			body: `{"z":1,"a":2,"m":{"y":3,"b":4}}`, ctype: "application/json",
		},
		{
			name: "post-json-unicode", desc: "Unicode is preserved exactly; no NFC or NFKC normalization",
			method: http.MethodPost, url: "https://gw.example.com/v1/tools/github/repos/acme/app/issues",
			body: `{"note":"café 日本語 é"}`, ctype: "application/json",
		},
		{
			name: "path-percent-encoded", desc: "Percent-encoding in the path is preserved, so /a%2Fb differs from /a/b",
			method: http.MethodGet, url: "https://gw.example.com/v1/tools/github/repos/acme/my%2Frepo/issues",
		},
		{
			name: "delete-destructive", desc: "Body-less DELETE on a destructive route",
			method: http.MethodDelete, url: "https://gw.example.com/v1/tools/github/repos/acme/app",
		},
	}

	for _, s := range specs {
		v, err := build(s.name, s.desc, s.method, s.url, s.body, s.ctype, priv, pub, keyID)
		if err != nil {
			fatal(fmt.Errorf("%s: %w", s.name, err))
		}
		corpus.Vectors = append(corpus.Vectors, *v)
	}

	// Negative vectors: a conformant verifier must reject each of these.
	// They are derived from a valid vector so the only difference is the one
	// under test.
	base := corpus.Vectors[2] // post-json

	corpus.Vectors = append(corpus.Vectors,
		mutate(base, "reject-tampered-body",
			"Body altered after signing; content-digest no longer matches",
			"digest_mismatch", func(v *vectors.Vector) {
				v.CanonicalBody = `{"assignee":null,"labels":["p1","triage"],"title":"Tampered"}`
			}),
		mutate(base, "reject-expired",
			"created is older than the 300s acceptance window",
			"request_expired", func(v *vectors.Vector) {
				v.Verify.NowUnix = fixedCreated + protocol.MaxRequestAgeSeconds + 60
			}),
		mutate(base, "reject-future-dated",
			"created is beyond the 60s future skew allowance",
			"request_not_yet_valid", func(v *vectors.Vector) {
				v.Verify.NowUnix = fixedCreated - protocol.MaxClockSkewSeconds - 60
			}),
		mutate(base, "reject-alg-on-wire",
			"alg is forbidden in Signature-Input; the algorithm comes from the credential",
			"signature_malformed", func(v *vectors.Vector) {
				v.SignatureInput += `;alg="ed25519"`
			}),
		mutate(base, "reject-foreign-tag",
			"tag must be agw-sig-v1, so a signature from another profile cannot be replayed in",
			"invalid_tag", func(v *vectors.Vector) {
				v.SignatureInput = replaceTag(v.SignatureInput, "some-other-profile")
			}),
	)

	data, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		fatal(err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fatal(err)
	}
	fmt.Printf("wrote %d vectors to %s\n", len(corpus.Vectors), *out)
}

func build(name, desc, method, rawURL, body, ctype string,
	priv ed25519.PrivateKey, pub ed25519.PublicKey, keyID string) (*vectors.Vector, error) {

	bodyBytes := []byte(body)

	var reader *bytes.Reader
	if len(bodyBytes) > 0 {
		reader = bytes.NewReader(bodyBytes)
	}

	var req *http.Request
	var err error
	if reader == nil {
		req, err = http.NewRequest(method, rawURL, nil)
	} else {
		req, err = http.NewRequest(method, rawURL, reader)
	}
	if err != nil {
		return nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}

	res, err := httpmsig.Sign(httpmsig.SignInput{
		Request:     req,
		Body:        bodyBytes,
		TenantID:    tenantID,
		AgentID:     agentID,
		RequestID:   fixedRequestID,
		TraceParent: fixedTrace,
		Nonce:       fixedNonce,
		PrivateKey:  priv,
		KeyID:       keyID,
		Created:     time.Unix(fixedCreated, 0).UTC(),
	})
	if err != nil {
		return nil, err
	}

	canonicalBody := ""
	contentDigest := ""
	if len(bodyBytes) > 0 {
		canonical := bodyBytes
		if ctype == "application/json" {
			canonical, err = jcs.Canonicalize(bodyBytes)
			if err != nil {
				return nil, err
			}
		}
		canonicalBody = string(canonical)
		contentDigest = digest.Compute(canonical)
	}

	headers := map[string]string{}
	for _, n := range []string{
		"X-Tenant-Id", "X-Agent-Id", "X-Request-Id",
		"X-Agent-Signature-Version", "Traceparent",
		"Content-Type", "Content-Digest",
	} {
		if v := req.Header.Get(n); v != "" {
			headers[n] = v
		}
	}

	return &vectors.Vector{
		Name: name, Description: desc,
		Method: method, URL: rawURL, Headers: headers,
		Body: body, ContentType: ctype,
		TenantID: tenantID, AgentID: agentID,
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
		KeyID:      keyID,
		Nonce:      fixedNonce, RequestID: fixedRequestID,
		Trace: fixedTrace, Created: fixedCreated,
		CanonicalBody: canonicalBody, ContentDigest: contentDigest,
		SignatureInput: res.SignatureInput,
		SignatureBase:  string(res.SignatureBase),
		Signature:      res.Signature,
		Verify:         vectors.VerifyExpectation{Accepted: true, NowUnix: fixedCreated + 5},
	}, nil
}

func mutate(base vectors.Vector, name, desc, reason string, fn func(*vectors.Vector)) vectors.Vector {
	v := base
	v.Name = name
	v.Description = desc
	v.Verify = vectors.VerifyExpectation{Accepted: false, Reason: reason, NowUnix: fixedCreated + 5}
	fn(&v)
	return v
}

func replaceTag(sigInput, tag string) string {
	i := bytes.LastIndex([]byte(sigInput), []byte(`;tag="`))
	if i < 0 {
		return sigInput
	}
	return sigInput[:i] + `;tag="` + tag + `"`
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "gen: %v\n", err)
	os.Exit(1)
}
