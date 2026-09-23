package httpmsig_test

import (
	"strings"
	"testing"

	"github.com/Aryan22g/agw/pkg/ags1/httpmsig"
)

// FuzzParseSignatureInput drives the Signature-Input parser with arbitrary
// input.
//
// This parser is the first code to touch a fully attacker-controlled header on
// an unauthenticated request, so it must never panic and never return a
// successful parse for input outside the profile. A panic here is a remote
// denial of service against the gateway.
func FuzzParseSignatureInput(f *testing.F) {
	f.Add(`sig1=("@method" "@authority" "@path" "@query" "x-agent-id" "x-tenant-id" "x-request-id" "x-agent-signature-version" "traceparent");created=1750000000;keyid="k";nonce="sT9nUq2vXmK4pLzR8bYwCd";tag="agw-sig-v1"`)
	f.Add(`sig1=();created=1;keyid="";nonce="";tag=""`)
	f.Add(`sig1=("@method"`)
	f.Add(`=`)
	f.Add(``)
	f.Add(`sig1`)
	f.Add(`sig1=(")`)
	f.Add(`sig1=("@method");created=99999999999999999999999999;keyid="k";nonce="n";tag="agw-sig-v1"`)
	f.Add(`sig1=("@method");created=1;keyid="a;b";nonce="c;d";tag="agw-sig-v1"`)
	f.Add(strings.Repeat("sig1=(", 100))
	f.Add(`sig1=("content-digest";sf);created=1;keyid="k";nonce="n";tag="agw-sig-v1"`)

	f.Fuzz(func(t *testing.T, input string) {
		parsed, err := httpmsig.ParseSignatureInput(input)

		if err != nil {
			if parsed != nil {
				t.Errorf("parser returned both a result and an error for %q", input)
			}
			return
		}

		// A successful parse must satisfy every profile invariant. Anything
		// that gets through with a missing field would be handed to the
		// verifier as if it were well formed.
		if parsed == nil {
			t.Fatalf("nil result with nil error for %q", input)
		}
		if parsed.Label == "" {
			t.Errorf("accepted %q with an empty label", input)
		}
		if len(parsed.Components) == 0 {
			t.Errorf("accepted %q with no covered components", input)
		}
		if parsed.Params.KeyID == "" {
			t.Errorf("accepted %q with an empty keyid", input)
		}
		if parsed.Params.Nonce == "" {
			t.Errorf("accepted %q with an empty nonce", input)
		}
		if parsed.Params.Tag != "agw-sig-v1" {
			t.Errorf("accepted %q with tag %q", input, parsed.Params.Tag)
		}
	})
}

// FuzzParseSignatureHeader drives the Signature header parser.
func FuzzParseSignatureHeader(f *testing.F) {
	f.Add(`sig1=:YWJjZA==:`)
	f.Add(`sig1=::`)
	f.Add(`YWJjZA==`)
	f.Add(``)
	f.Add(`=`)
	f.Add(`sig1=:`)
	f.Add(`sig1=:!!!!:`)
	f.Add(strings.Repeat(":", 1000))

	f.Fuzz(func(t *testing.T, input string) {
		label, sig, err := httpmsig.ParseSignatureHeader(input)
		if err != nil {
			return
		}
		if label == "" {
			t.Errorf("accepted %q with an empty label", input)
		}
		if len(sig) == 0 {
			t.Errorf("accepted %q with an empty signature", input)
		}
	})
}
