package httpmsig_test

import (
	"strings"
	"testing"

	"github.com/Aryan22g/agw/pkg/ags1/canonicalhttp"

	"github.com/Aryan22g/agw/pkg/ags1/httpmsig"
)

const validComponents = `("@method" "@authority" "@path" "@query" "x-agent-id" "x-tenant-id" "x-request-id" "x-agent-signature-version" "traceparent")`

func validInput(params string) string {
	return "sig1=" + validComponents + params
}

const goodParams = `;created=1710000000;keyid="k";nonce="0123456789012345678901";tag="agw-sig-v1"`

func TestParsesValidSignatureInput(t *testing.T) {
	in, err := httpmsig.ParseSignatureInput(validInput(goodParams))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if in.Label != "sig1" {
		t.Errorf("label = %q, want sig1", in.Label)
	}
	if len(in.Components) != 9 {
		t.Errorf("components = %d, want 9", len(in.Components))
	}
	if in.Params.KeyID != "k" || in.Params.Created != 1710000000 {
		t.Errorf("params parsed incorrectly: %+v", in.Params)
	}
}

// TestMalformedSignatureInputRejected walks the shapes a hostile or buggy
// client can produce. Each must be a clean rejection, never a partial parse.
func TestMalformedSignatureInputRejected(t *testing.T) {
	cases := map[string]string{
		"empty":                 "",
		"no label":              validComponents + goodParams,
		"no components":         "sig1=" + goodParams,
		"unterminated list":     `sig1=("@method"` + goodParams,
		"empty component list":  "sig1=()" + goodParams,
		"unquoted component":    `sig1=(@method "@path")` + goodParams,
		"no params":             "sig1=" + validComponents,
		"missing created":       validInput(`;keyid="k";nonce="0123456789012345678901";tag="agw-sig-v1"`),
		"missing keyid":         validInput(`;created=1;nonce="0123456789012345678901";tag="agw-sig-v1"`),
		"missing nonce":         validInput(`;created=1;keyid="k";tag="agw-sig-v1"`),
		"missing tag":           validInput(`;created=1;keyid="k";nonce="0123456789012345678901"`),
		"duplicate param":       validInput(`;created=1;created=2;keyid="k";nonce="0123456789012345678901";tag="agw-sig-v1"`),
		"unknown param":         validInput(`;created=1;keyid="k";nonce="0123456789012345678901";tag="agw-sig-v1";extra="x"`),
		"alg present":           validInput(`;created=1;keyid="k";nonce="0123456789012345678901";tag="agw-sig-v1";alg="ed25519"`),
		"non-numeric created":   validInput(`;created=soon;keyid="k";nonce="0123456789012345678901";tag="agw-sig-v1"`),
		"foreign tag":           validInput(`;created=1;keyid="k";nonce="0123456789012345678901";tag="other"`),
		"unsupported component": `sig1=("@method" "x-evil")` + goodParams,
		"nonce too short":       validInput(`;created=1;keyid="k";nonce="short";tag="agw-sig-v1"`),
	}

	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := httpmsig.ParseSignatureInput(input); err == nil {
				t.Errorf("malformed input was accepted: %s", input)
			}
		})
	}
}

// TestContentDigestRequiresSFParam: content-digest must carry ;sf, and
// nothing else may.
func TestContentDigestSFParamEnforced(t *testing.T) {
	withBody := `sig1=("@method" "@authority" "@path" "@query" "content-digest" "content-type" "x-agent-id" "x-tenant-id" "x-request-id" "x-agent-signature-version" "traceparent")` + goodParams
	if _, err := httpmsig.ParseSignatureInput(withBody); err == nil {
		t.Error("content-digest without ;sf was accepted")
	}

	wrongSF := `sig1=("@method";sf "@authority" "@path" "@query" "x-agent-id" "x-tenant-id" "x-request-id" "x-agent-signature-version" "traceparent")` + goodParams
	if _, err := httpmsig.ParseSignatureInput(wrongSF); err == nil {
		t.Error("@method carrying ;sf was accepted")
	}
}

// TestParamSplitRespectsQuotes: a nonce or keyid containing ';' must not be
// able to break the parameter parse.
func TestParamSplitRespectsQuotes(t *testing.T) {
	in, err := httpmsig.ParseSignatureInput(
		validInput(`;created=1710000000;keyid="key;with;semicolons";nonce="0123456789012345678901";tag="agw-sig-v1"`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if in.Params.KeyID != "key;with;semicolons" {
		t.Errorf("keyid = %q, want the full quoted value", in.Params.KeyID)
	}
}

func TestSignatureHeaderParsing(t *testing.T) {
	label, sig, err := httpmsig.ParseSignatureHeader("sig1=:YWJjZA==:")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if label != "sig1" {
		t.Errorf("label = %q, want sig1", label)
	}
	if string(sig) != "abcd" {
		t.Errorf("signature = %q, want abcd", sig)
	}
}

// TestSignatureHeaderRejectsBareBase64 covers the exact bug this replaced:
// the header is a structured-field byte sequence, not a bare base64 string.
func TestSignatureHeaderRejectsMalformed(t *testing.T) {
	for _, bad := range []string{
		"",
		"YWJjZA==",        // bare base64, no label or colons
		"sig1=YWJjZA==",   // no colons
		"sig1=::",         // empty
		"sig1=:not b64!:", // not base64
		"=:YWJjZA==:",     // no label
	} {
		if _, _, err := httpmsig.ParseSignatureHeader(bad); err == nil {
			t.Errorf("malformed Signature header %q was accepted", bad)
		}
	}
}

// TestLabelMismatchRejected: mismatched labels mean the parameters being
// validated are not the ones that were signed.
func TestLabelMismatchRejected(t *testing.T) {
	_, _, err := httpmsig.ParseHeaders(validInput(goodParams), "sig2=:YWJjZA==:")
	if err == nil {
		t.Fatal("mismatched Signature and Signature-Input labels were accepted")
	}
	if !strings.Contains(err.Error(), "label") {
		t.Errorf("error %v does not mention the label mismatch", err)
	}
}

func TestBuildSignatureInputRoundTrips(t *testing.T) {
	built, err := httpmsig.BuildSignatureInput("sig1",
		[]string{"@method", "@authority", "@path", "@query",
			"x-agent-id", "x-tenant-id", "x-request-id",
			"x-agent-signature-version", "traceparent"},
		canonicalParams())
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	parsed, err := httpmsig.ParseSignatureInput(built)
	if err != nil {
		t.Fatalf("the builder produced input the parser rejects: %v\n%s", err, built)
	}
	if parsed.Params.Nonce != "0123456789012345678901" {
		t.Errorf("nonce did not survive the round trip: %q", parsed.Params.Nonce)
	}
}

func canonicalParams() canonicalhttp.SignatureParams {
	return canonicalhttp.SignatureParams{
		Created: 1710000000,
		KeyID:   "k",
		Nonce:   "0123456789012345678901",
		Tag:     "agw-sig-v1",
	}
}
