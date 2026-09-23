package keys_test

import (
	"encoding/base64"
	"testing"

	"github.com/Aryan22g/agw/pkg/ags1/keys"
)

// TestRFC8037KnownAnswer pins the thumbprint derivation against the published
// Ed25519 example in RFC 8037 Appendix A.3.
//
// This is the single most important cross-language test in the profile. `kid`
// is how a signature names the credential it should be checked against, so
// every AGS1 SDK -- Go, Python, TypeScript, Rust -- must derive this exact
// string from this exact key. If an implementation drifts here, its
// signatures resolve to the wrong credential or to none at all, and the
// failure looks like an unrelated key-lookup bug.
func TestRFC8037KnownAnswer(t *testing.T) {
	const (
		x    = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
		want = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	)

	jwk := &keys.JWK{Kty: "OKP", Crv: "Ed25519", X: x}

	got, err := jwk.Thumbprint()
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got != want {
		t.Errorf("thumbprint = %q, want %q (RFC 8037 A.3)", got, want)
	}
}

// TestThumbprintInputIsExact pins the canonical JSON bytes the hash is taken
// over, so a refactor cannot quietly change member order or spacing.
func TestThumbprintInputIsExact(t *testing.T) {
	const x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	want := `{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`

	if got := string(keys.ThumbprintInput(x)); got != want {
		t.Errorf("thumbprint input =\n%s\nwant\n%s", got, want)
	}
}

func TestGenerateDerivesMatchingKeyID(t *testing.T) {
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	jwk, err := keys.PublicKeyToJWK(kp.PublicKey)
	if err != nil {
		t.Fatalf("to jwk: %v", err)
	}
	if jwk.Kid != kp.KeyID {
		t.Errorf("keypair kid %q does not match JWK kid %q", kp.KeyID, jwk.Kid)
	}
	if err := jwk.Validate(); err != nil {
		t.Errorf("generated JWK failed validation: %v", err)
	}
}

// TestForgedKidRejected covers the case that makes kid security-relevant: a
// JWK whose declared kid does not hash from its own key material.
func TestForgedKidRejected(t *testing.T) {
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	jwk, err := keys.PublicKeyToJWK(kp.PublicKey)
	if err != nil {
		t.Fatalf("to jwk: %v", err)
	}

	jwk.Kid = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k" // some other key's kid
	if err := jwk.Validate(); err == nil {
		t.Fatal("a JWK claiming another key's kid was accepted")
	}
}

func TestRoundTripPublicKey(t *testing.T) {
	kp, err := keys.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	jwk, err := keys.PublicKeyToJWK(kp.PublicKey)
	if err != nil {
		t.Fatalf("to jwk: %v", err)
	}

	back, err := jwk.PublicKey()
	if err != nil {
		t.Fatalf("from jwk: %v", err)
	}
	if base64.RawURLEncoding.EncodeToString(back) != base64.RawURLEncoding.EncodeToString(kp.PublicKey) {
		t.Error("public key did not survive the JWK round trip")
	}
}

func TestNonEd25519JWKRejected(t *testing.T) {
	for _, jwk := range []*keys.JWK{
		{Kty: "EC", Crv: "P-256", X: "abc"},
		{Kty: "OKP", Crv: "X25519", X: "abc"},
		{Kty: "OKP", Crv: "Ed25519", X: ""},
	} {
		if err := jwk.Validate(); err == nil {
			t.Errorf("JWK %+v was accepted; AGS1 permits only OKP/Ed25519", jwk)
		}
	}
}
