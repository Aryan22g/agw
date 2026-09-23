package confine

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

func fixedLookup(addrs ...string) LookupFunc {
	return func(context.Context, string) ([]netip.Addr, error) {
		out := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

func newTestResolver(t *testing.T, lookup LookupFunc, permit ...string) *Resolver {
	t.Helper()
	r, err := NewResolver(ResolverConfig{Guard: mustGuard(t, permit...), Lookup: lookup})
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	return r
}

// TestDNSRebindingIsRefused is the reason Resolve exists in this shape.
//
// A permitted hostname whose DNS answer includes an address the guard refuses
// must fail entirely. Returning only the addresses that passed would make the
// control depend on which answer a resolver happened to order first.
func TestDNSRebindingIsRefused(t *testing.T) {
	cases := map[string][]string{
		"metadata second":    {"140.82.121.4", "169.254.169.254"},
		"metadata first":     {"169.254.169.254", "140.82.121.4"},
		"private among many": {"1.1.1.1", "8.8.8.8", "10.0.0.1"},
		"mapped metadata":    {"140.82.121.4", "::ffff:169.254.169.254"},
		"loopback":           {"127.0.0.1"},
	}

	for name, addrs := range cases {
		t.Run(name, func(t *testing.T) {
			r := newTestResolver(t, fixedLookup(addrs...))
			got, err := r.Resolve(context.Background(), "totally-legit.example.com")
			if err == nil {
				t.Fatalf("resolved to %v, expected refusal", got)
			}
		})
	}
}

func TestCleanResolutionIsAccepted(t *testing.T) {
	r := newTestResolver(t, fixedLookup("140.82.121.4", "140.82.121.5"))

	addrs, err := r.Resolve(context.Background(), "api.github.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("got %d addresses, want 2", len(addrs))
	}
}

// TestIPLiteralsSkipResolutionButNotTheGuard covers the shortcut path: an
// IP literal must never reach the resolver, and must still be checked.
func TestIPLiteralsSkipResolutionButNotTheGuard(t *testing.T) {
	poisoned := func(context.Context, string) ([]netip.Addr, error) {
		t.Fatal("an IP literal was sent to the resolver")
		return nil, nil
	}
	r := newTestResolver(t, poisoned)

	if _, err := r.Resolve(context.Background(), "140.82.121.4"); err != nil {
		t.Errorf("public literal refused: %v", err)
	}

	_, err := r.Resolve(context.Background(), "169.254.169.254")
	if err == nil {
		t.Error("metadata literal was permitted")
	}
	if !errors.Is(err, ErrLinkLocal) {
		t.Errorf("got %v, want ErrLinkLocal", err)
	}
}

func TestEmptyResolutionIsRefused(t *testing.T) {
	r := newTestResolver(t, func(context.Context, string) ([]netip.Addr, error) {
		return nil, nil
	})
	if _, err := r.Resolve(context.Background(), "nowhere.example.com"); err == nil {
		t.Error("a hostname resolving to nothing was accepted")
	}
}

func TestNarrowExemptionAppliesThroughResolution(t *testing.T) {
	r := newTestResolver(t, fixedLookup("10.1.2.7"), "10.1.2.0/24")

	if _, err := r.Resolve(context.Background(), "internal.example.com"); err != nil {
		t.Errorf("exempted private address refused: %v", err)
	}
}
