package vectors_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/Aryan22g/agw/pkg/ags1/canonicalhttp"
	"github.com/Aryan22g/agw/pkg/ags1/digest"
	"github.com/Aryan22g/agw/pkg/ags1/httpmsig"
	"github.com/Aryan22g/agw/pkg/ags1/jcs"
	"github.com/Aryan22g/agw/pkg/ags1/keys"
	"github.com/Aryan22g/agw/pkg/ags1/vectors"
)

func loadCorpus(t *testing.T) vectors.Corpus {
	t.Helper()

	data, err := os.ReadFile("ags1-v1.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}

	var c vectors.Corpus
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if len(c.Vectors) == 0 {
		t.Fatal("corpus is empty")
	}
	return c
}

// TestSigningMatchesCorpus is the regression guard on the wire format. If a
// refactor changes a single byte of the signature base, this fails -- which is
// the whole point, because that byte is a wire-breaking change that would
// silently invalidate every SDK in the field.
func TestSigningMatchesCorpus(t *testing.T) {
	corpus := loadCorpus(t)

	for _, v := range corpus.Vectors {
		if !v.Verify.Accepted {
			continue // negative vectors are mutated; re-signing them is meaningless
		}

		t.Run(v.Name, func(t *testing.T) {
			priv, err := keys.DecodePrivateKey(v.PrivateKey)
			if err != nil {
				t.Fatalf("decode key: %v", err)
			}

			body := []byte(v.Body)
			var req *http.Request
			if len(body) > 0 {
				req, err = http.NewRequest(v.Method, v.URL, bytes.NewReader(body))
			} else {
				req, err = http.NewRequest(v.Method, v.URL, nil)
			}
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			if v.ContentType != "" {
				req.Header.Set("Content-Type", v.ContentType)
			}

			res, err := httpmsig.Sign(httpmsig.SignInput{
				Request:     req,
				Body:        body,
				TenantID:    v.TenantID,
				AgentID:     v.AgentID,
				RequestID:   v.RequestID,
				TraceParent: v.Trace,
				Nonce:       v.Nonce,
				PrivateKey:  priv,
				KeyID:       v.KeyID,
				Created:     time.Unix(v.Created, 0).UTC(),
			})
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			if string(res.SignatureBase) != v.SignatureBase {
				t.Errorf("signature base drifted from the corpus:\n--- want ---\n%s\n--- got ---\n%s",
					v.SignatureBase, res.SignatureBase)
			}
			if res.SignatureInput != v.SignatureInput {
				t.Errorf("signature-input:\n want %s\n  got %s", v.SignatureInput, res.SignatureInput)
			}
			if res.Signature != v.Signature {
				t.Errorf("signature:\n want %s\n  got %s", v.Signature, res.Signature)
			}
			if v.ContentDigest != "" && res.ContentDigest != v.ContentDigest {
				t.Errorf("content-digest:\n want %s\n  got %s", v.ContentDigest, res.ContentDigest)
			}
			if v.CanonicalBody != "" && string(res.Body) != v.CanonicalBody {
				t.Errorf("canonical body:\n want %s\n  got %s", v.CanonicalBody, res.Body)
			}
		})
	}
}

// TestVerificationMatchesCorpus runs the verifier over every vector and checks
// the accept/reject expectation. This is the check another language's SDK must
// also pass.
func TestVerificationMatchesCorpus(t *testing.T) {
	corpus := loadCorpus(t)

	for _, v := range corpus.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			pub, err := keys.DecodePublicKey(v.PublicKey)
			if err != nil {
				t.Fatalf("decode public key: %v", err)
			}

			body := []byte(v.CanonicalBody)
			var req *http.Request
			if len(body) > 0 {
				req, err = http.NewRequest(v.Method, v.URL, bytes.NewReader(body))
			} else {
				req, err = http.NewRequest(v.Method, v.URL, nil)
			}
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			for name, value := range v.Headers {
				req.Header.Set(name, value)
			}
			req.Host = req.URL.Host

			canon, err := canonicalhttp.FromHTTPRequest(req, body)
			if err != nil {
				if v.Verify.Accepted {
					t.Fatalf("canonicalize: %v", err)
				}
				return // a rejection at canonicalization is still a rejection
			}

			_, err = httpmsig.Verify(httpmsig.VerifyInput{
				Request:              canon,
				SignatureInputHeader: v.SignatureInput,
				SignatureHeader:      v.Signature,
				PublicKey:            pub,
				Now:                  time.Unix(v.Verify.NowUnix, 0).UTC(),
			})

			if v.Verify.Accepted && err != nil {
				t.Errorf("vector should verify but did not: %v", err)
			}
			if !v.Verify.Accepted && err == nil {
				t.Errorf("vector should have been rejected (%s) but verified", v.Verify.Reason)
			}
		})
	}
}

// TestCorpusSelfConsistency checks the corpus itself, so a bad regeneration is
// caught rather than becoming the new baseline.
func TestCorpusSelfConsistency(t *testing.T) {
	corpus := loadCorpus(t)

	if corpus.Profile != "AGS1" || corpus.Tag != "agw-sig-v1" {
		t.Errorf("corpus declares profile %q tag %q", corpus.Profile, corpus.Tag)
	}

	seen := map[string]bool{}
	for _, v := range corpus.Vectors {
		if seen[v.Name] {
			t.Errorf("duplicate vector name %q", v.Name)
		}
		seen[v.Name] = true

		if v.SignatureBase == "" || v.Signature == "" || v.SignatureInput == "" {
			t.Errorf("vector %q is missing expected outputs", v.Name)
		}

		// Key material must be self-consistent: the declared kid must be the
		// thumbprint of the declared public key.
		pub, err := keys.DecodePublicKey(v.PublicKey)
		if err != nil {
			t.Errorf("vector %q: %v", v.Name, err)
			continue
		}
		kid, err := keys.KeyID(pub)
		if err != nil {
			t.Errorf("vector %q: %v", v.Name, err)
			continue
		}
		if kid != v.KeyID {
			t.Errorf("vector %q declares kid %q but its public key hashes to %q", v.Name, v.KeyID, kid)
		}

		// The canonical body must actually be JCS-canonical and match the
		// declared digest.
		//
		// Only for positive vectors: a negative vector such as
		// reject-tampered-body is deliberately inconsistent, since the
		// mismatch between body and digest is exactly what it tests.
		if v.Verify.Accepted && v.CanonicalBody != "" && v.ContentType == "application/json" {
			if !jcs.IsCanonical([]byte(v.CanonicalBody)) {
				t.Errorf("vector %q canonical body is not JCS-canonical", v.Name)
			}
			if got := digest.Compute([]byte(v.CanonicalBody)); got != v.ContentDigest {
				t.Errorf("vector %q digest %s does not match its canonical body (%s)",
					v.Name, v.ContentDigest, got)
			}
		}
	}

	var positives, negatives int
	for _, v := range corpus.Vectors {
		if v.Verify.Accepted {
			positives++
		} else {
			negatives++
		}
	}
	if positives == 0 || negatives == 0 {
		t.Errorf("corpus needs both positive and negative vectors; got %d/%d", positives, negatives)
	}
}

// TestKeyMaterialIsTheDocumentedTestKey guards against someone regenerating
// the corpus with a real key.
func TestKeyMaterialIsTheDocumentedTestKey(t *testing.T) {
	corpus := loadCorpus(t)

	want := base64.StdEncoding.EncodeToString(
		append([]byte{
			0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
			0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
			0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
			0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
		}, mustPublic(t, corpus.Vectors[0].PublicKey)...))

	if corpus.Vectors[0].PrivateKey != want {
		t.Error("corpus was generated with a key other than the documented test seed")
	}
}

func mustPublic(t *testing.T, encoded string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	return raw
}
