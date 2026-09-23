package confine

import (
	"errors"
	"net/netip"
	"testing"
)

func mustGuard(t *testing.T, permit ...string) *Guard {
	t.Helper()
	g, err := NewGuard(permit)
	if err != nil {
		t.Fatalf("NewGuard(%v): %v", permit, err)
	}
	return g
}

// TestMetadataEndpointIsRefused is the single most important test in this
// package. 169.254.169.254 is where the July 2026 Hugging Face intruder read
// AWS credentials after gaining code execution.
func TestMetadataEndpointIsRefused(t *testing.T) {
	g := mustGuard(t)

	for _, spelling := range []string{
		"169.254.169.254",        // the address itself
		"::ffff:169.254.169.254", // IPv4-mapped IPv6
		"169.254.169.253",        // anywhere else in link-local
		"fe80::1",                // IPv6 link-local
		"169.254.0.1",
	} {
		t.Run(spelling, func(t *testing.T) {
			addr, err := netip.ParseAddr(spelling)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if err := g.Check(addr); err == nil {
				t.Fatalf("%s was permitted", spelling)
			}
		})
	}
}

func TestStructuralDenials(t *testing.T) {
	g := mustGuard(t)

	tests := []struct {
		addr string
		want error
	}{
		{"127.0.0.1", ErrLoopback},
		{"::1", ErrLoopback},
		{"::ffff:127.0.0.1", ErrLoopback},
		{"10.0.0.5", ErrPrivate},
		{"172.16.0.1", ErrPrivate},
		{"172.31.255.254", ErrPrivate},
		{"192.168.1.1", ErrPrivate},
		{"::ffff:10.0.0.5", ErrPrivate},
		{"fd00::1", ErrPrivate},
		{"169.254.169.254", ErrLinkLocal},
		{"0.0.0.0", ErrUnspecified},
		{"::", ErrUnspecified},
		{"224.0.0.1", ErrMulticast},
		{"ff02::1", ErrMulticast},
		{"100.64.0.1", ErrCarrierNAT},
		{"100.127.255.255", ErrCarrierNAT},
		{"64:ff9b::a9fe:a9fe", ErrNAT64}, // 169.254.169.254 embedded in NAT64
		{"64:ff9b:1::1", ErrNAT64},
	}

	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			addr := netip.MustParseAddr(tc.addr)
			err := g.Check(addr)
			if err == nil {
				t.Fatalf("%s was permitted, want %v", tc.addr, tc.want)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("%s: got %v, want %v", tc.addr, err, tc.want)
			}
		})
	}
}

func TestPublicAddressesArePermitted(t *testing.T) {
	g := mustGuard(t)

	for _, s := range []string{
		"140.82.121.4", // github
		"1.1.1.1",
		"2606:4700::1111",
		"8.8.8.8",
		"172.15.0.1",     // just outside 172.16/12
		"172.32.0.1",     // just outside 172.16/12
		"100.63.255.255", // just outside 100.64/10
		"100.128.0.0",    // just outside 100.64/10
	} {
		t.Run(s, func(t *testing.T) {
			if err := g.Check(netip.MustParseAddr(s)); err != nil {
				t.Errorf("%s was refused: %v", s, err)
			}
		})
	}
}

// TestNarrowExemptionWorks covers the legitimate case: an operator who needs
// one internal service reachable.
func TestNarrowExemptionWorks(t *testing.T) {
	g := mustGuard(t, "10.1.2.0/24")

	if err := g.Check(netip.MustParseAddr("10.1.2.7")); err != nil {
		t.Errorf("exempted address was refused: %v", err)
	}
	// Neighbouring private space is still denied.
	if err := g.Check(netip.MustParseAddr("10.1.3.7")); err == nil {
		t.Error("an address outside the exemption was permitted")
	}
	// The exemption does not reopen link-local.
	if err := g.Check(netip.MustParseAddr("169.254.169.254")); err == nil {
		t.Error("exempting a private subnet also permitted the metadata endpoint")
	}
}

// TestExemptionCannotBeAWildcard guards the failure mode where someone
// switches the control off while appearing to configure it.
func TestExemptionCannotBeAWildcard(t *testing.T) {
	for _, bad := range []string{
		"0.0.0.0/0",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::/0",
		"fd00::/8",
	} {
		t.Run(bad, func(t *testing.T) {
			if _, err := NewGuard([]string{bad}); err == nil {
				t.Errorf("%s was accepted as a narrow exemption", bad)
			}
		})
	}
}

func TestReasonCodesAreStable(t *testing.T) {
	cases := map[error]string{
		nil:             "allowed",
		ErrLinkLocal:    "metadata_endpoint",
		ErrLoopback:     "loopback_denied",
		ErrPrivate:      "private_address_denied",
		ErrCarrierNAT:   "carrier_nat_denied",
		ErrNAT64:        "nat64_denied",
		ErrMulticast:    "multicast_denied",
		ErrUnspecified:  "invalid_destination",
		ErrNotPermitted: "not_in_allowlist",
	}
	for err, want := range cases {
		if got := Reason(err); got != want {
			t.Errorf("Reason(%v) = %q, want %q", err, got, want)
		}
	}
}
