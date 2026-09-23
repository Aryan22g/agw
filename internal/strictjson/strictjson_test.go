package strictjson

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestNoDuplicates(t *testing.T) {
	ok := []string{`{"a":1,"b":{"a":2,"c":[{"a":3},{"a":4}]},"c":"a"}`, `[{"x":1},{"x":2}]`, `"s"`, `3`, `{"x":[1,"x",{"x":null}],"y":{}}`}
	for _, s := range ok {
		if err := NoDuplicates([]byte(s)); err != nil {
			t.Errorf("%s: %v", s, err)
		}
	}
	bad := []string{`{"a":1,"a":2}`, `{"o":{"k":1,"k":1}}`, `[{"z":1},{"z":1,"z":2}]`, `{"a":1} {"b":2}`}
	for _, s := range bad {
		if err := NoDuplicates([]byte(s)); err == nil {
			t.Errorf("%s: not rejected", s)
		}
	}
}

func TestExactNames(t *testing.T) {
	var obj map[string]json.RawMessage
	_ = json.Unmarshal([]byte(`{"method":"a","Method":"b","other":1}`), &obj)
	if err := ExactNames(obj, "method", "params"); !errors.Is(err, ErrCaseVariant) {
		t.Fatalf("case variant not rejected: %v", err)
	}
	obj = nil // Unmarshal into an existing map merges; start clean
	_ = json.Unmarshal([]byte(`{"method":"a","METHODS":1}`), &obj)
	if err := ExactNames(obj, "method"); err != nil {
		t.Fatalf("a different name was rejected: %v", err)
	}
}
