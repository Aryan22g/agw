package jcs_test

import (
	"testing"

	"github.com/Aryan22g/agw/pkg/ags1/jcs"
)

// FuzzCanonicalize drives the JSON canonicalizer with arbitrary bytes.
//
// Bodies are attacker-controlled, and canonicalization runs before any
// signature check, so this must never panic. It must also be idempotent:
// canonicalizing already-canonical output has to be a no-op, or the digest a
// sender computes could differ from the one a verifier recomputes.
func FuzzCanonicalize(f *testing.F) {
	f.Add([]byte(`{"a":1,"b":[1,2,3]}`))
	f.Add([]byte(`{"z":{"y":{"x":null}}}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`"just a string"`))
	f.Add([]byte(`1e400`))
	f.Add([]byte(`{"k":"café 日本語"}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Add([]byte(``))
	f.Add([]byte(`{`))

	f.Fuzz(func(t *testing.T, input []byte) {
		out, err := jcs.Canonicalize(input)
		if err != nil {
			return
		}

		again, err := jcs.Canonicalize(out)
		if err != nil {
			t.Fatalf("canonical output failed to re-canonicalize: %v\ninput: %q\noutput: %q",
				err, input, out)
		}
		if string(again) != string(out) {
			t.Fatalf("canonicalization is not idempotent:\nfirst:  %q\nsecond: %q", out, again)
		}
	})
}
