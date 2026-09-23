package digest_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/Aryan22g/agw/pkg/ags1/digest"
	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

func TestComputeMatchesSHA256(t *testing.T) {
	body := []byte(`{"a":1}`)
	sum := sha256.Sum256(body)
	want := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"

	if got := digest.Compute(body); got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestComputeOverEmptyBody(t *testing.T) {
	// A body-less request has no Content-Digest at all, but the empty digest
	// must still be well formed for callers that compute it explicitly.
	if got := digest.Compute(nil); got == "" {
		t.Error("empty body produced no digest")
	}
	if _, err := digest.Parse(digest.Compute(nil)); err != nil {
		t.Errorf("digest of an empty body does not parse: %v", err)
	}
}

func TestValidateAcceptsMatching(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	if err := digest.Validate(body, digest.Compute(body)); err != nil {
		t.Errorf("matching digest rejected: %v", err)
	}
}

func TestValidateRejectsMismatch(t *testing.T) {
	err := digest.Validate([]byte(`{"hello":"world"}`), digest.Compute([]byte(`{"hello":"there"}`)))
	if !errors.Is(err, protocol.ErrContentDigestMismatch) {
		t.Errorf("got %v, want ErrContentDigestMismatch", err)
	}
}

// TestSingleByteChangeDetected: the digest is the only thing binding the body
// to the signature, so it must be sensitive to any change.
func TestSingleByteChangeDetected(t *testing.T) {
	body := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	original := digest.Compute(body)

	for i := range body {
		mutated := append([]byte(nil), body...)
		mutated[i] ^= 0x01

		if err := digest.Validate(mutated, original); err == nil {
			t.Fatalf("a one-bit change at offset %d was not detected", i)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"",
		"sha-256=abc",             // missing colons
		"sha-256=::",              // empty digest
		"sha-512=:abc:",           // unsupported algorithm
		"sha-256=:not base64!!!:", // not base64
		":abc:",                   // no algorithm
	} {
		if _, err := digest.Parse(bad); err == nil {
			t.Errorf("malformed digest %q was accepted", bad)
		}
	}
}

// TestNormalizeStripsIncidentalWhitespace covers what the ;sf parameter is
// for: an intermediary adding whitespace must not break a valid signature.
func TestNormalizeStripsIncidentalWhitespace(t *testing.T) {
	body := []byte(`{"a":1}`)
	canonical := digest.Compute(body)

	got, err := digest.Normalize("  " + canonical + "  ")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if got != canonical {
		t.Errorf("normalize gave %q, want %q", got, canonical)
	}
}

func TestUnsupportedAlgorithmRejected(t *testing.T) {
	// A verifier that accepts a caller-selected algorithm can be talked down
	// to the weakest one it knows.
	if err := digest.Validate([]byte("x"), "md5=:1B2M2Y8AsgTpgAmY7PhCfg==:"); err == nil {
		t.Error("a non-sha-256 digest algorithm was accepted")
	}
}
