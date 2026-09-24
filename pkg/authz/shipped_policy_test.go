package authz_test

import (
	"testing"

	"github.com/Aryan22g/agw/pkg/authz"
)

// TestShippedPolicyLoads guards the example policy: a config we ship that
// does not load would break everyone who starts from it.
func TestShippedPolicyLoads(t *testing.T) {
	policies, err := authz.LoadPolicyDir("../../configs/gateway/policies")
	if err != nil {
		t.Fatalf("shipped policy dir failed to load: %v", err)
	}
	if _, ok := policies["tenant-alpha"]; !ok {
		t.Fatalf("tenant-alpha policy not loaded; got %v", keysOf(policies))
	}
}

func keysOf(m map[string]*authz.Policy) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
