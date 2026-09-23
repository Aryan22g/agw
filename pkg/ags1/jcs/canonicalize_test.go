package jcs_test

import (
	"errors"
	"testing"

	"github.com/Aryan22g/agw/pkg/ags1/jcs"
	"github.com/Aryan22g/agw/pkg/ags1/protocol"
)

func TestCanonicalOrdering(t *testing.T) {
	got, err := jcs.Canonicalize([]byte(`{"b":2,"a":1,"c":{"z":26,"y":25}}`))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"a":1,"b":2,"c":{"y":25,"z":26}}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

// TestDuplicateKeysRejected: duplicate keys are ambiguous across parsers, so
// a signer and verifier could canonicalize the same bytes differently.
func TestDuplicateKeysRejected(t *testing.T) {
	_, err := jcs.Canonicalize([]byte(`{"a":1,"a":2}`))
	if !errors.Is(err, protocol.ErrDuplicateJSONKey) {
		t.Errorf("got %v, want ErrDuplicateJSONKey", err)
	}
}

func TestNestedDuplicateKeysRejected(t *testing.T) {
	_, err := jcs.Canonicalize([]byte(`{"outer":{"a":1,"a":2}}`))
	if !errors.Is(err, protocol.ErrDuplicateJSONKey) {
		t.Errorf("got %v, want ErrDuplicateJSONKey", err)
	}
}

func TestDuplicateKeysInsideArrayRejected(t *testing.T) {
	_, err := jcs.Canonicalize([]byte(`{"list":[{"a":1,"a":2}]}`))
	if !errors.Is(err, protocol.ErrDuplicateJSONKey) {
		t.Errorf("got %v, want ErrDuplicateJSONKey", err)
	}
}

func TestInvalidUTF8Rejected(t *testing.T) {
	_, err := jcs.Canonicalize([]byte{'{', '"', 'a', '"', ':', '"', 0xff, 0xfe, '"', '}'})
	if !errors.Is(err, protocol.ErrInvalidUTF8) {
		t.Errorf("got %v, want ErrInvalidUTF8", err)
	}
}

func TestTrailingContentRejected(t *testing.T) {
	if _, err := jcs.Canonicalize([]byte(`{"a":1} trailing`)); err == nil {
		t.Error("trailing content after the JSON document was accepted")
	}
}

func TestEmptyInputRejected(t *testing.T) {
	if _, err := jcs.Canonicalize(nil); !errors.Is(err, protocol.ErrInvalidJSON) {
		t.Errorf("got %v, want ErrInvalidJSON", err)
	}
}

// TestUnicodePreserved: JCS must not apply NFC/NFKC, since normalizing would
// change the bytes the sender digested.
func TestUnicodePreserved(t *testing.T) {
	// U+00E9 (precomposed) and U+0065 U+0301 (decomposed) must stay distinct.
	precomposed, err := jcs.Canonicalize([]byte("{\"k\":\"café\"}"))
	if err != nil {
		t.Fatalf("precomposed: %v", err)
	}
	decomposed, err := jcs.Canonicalize([]byte("{\"k\":\"café\"}"))
	if err != nil {
		t.Fatalf("decomposed: %v", err)
	}
	if string(precomposed) == string(decomposed) {
		t.Error("JCS normalized Unicode; precomposed and decomposed forms must stay distinct")
	}
}

func TestDeterministic(t *testing.T) {
	input := []byte(`{"z":[3,1,2],"a":{"n":1.5,"s":"x"},"m":true}`)

	first, err := jcs.Canonicalize(input)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := jcs.Canonicalize(input)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if string(again) != string(first) {
			t.Fatalf("canonicalization is not deterministic:\n%s\n%s", first, again)
		}
	}
}

func TestIsCanonical(t *testing.T) {
	if !jcs.IsCanonical([]byte(`{"a":1,"b":2}`)) {
		t.Error("already-canonical input reported as non-canonical")
	}
	if jcs.IsCanonical([]byte(`{"b":2,"a":1}`)) {
		t.Error("unordered input reported as canonical")
	}
}

func TestInvalidJSONRejected(t *testing.T) {
	for _, bad := range []string{`{`, `{"a":}`, `{'a':1}`, `[1,2,`, `nope`} {
		if _, err := jcs.Canonicalize([]byte(bad)); err == nil {
			t.Errorf("invalid JSON %q was accepted", bad)
		}
	}
}
