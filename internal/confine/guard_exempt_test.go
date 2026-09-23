package confine

import (
	"net/netip"
	"strings"
	"testing"
)

// TestPermitPrivateCannotReopenStructuralDenials pins the fix for a defect the
// gym found by generating the policy an operator in a hurry would write.
//
// Guard.Check consults exemptions BEFORE every structural denial, and the only
// thing NewGuard used to check was prefix width. 169.254.169.0/24 is a /24 --
// narrow enough to look considered -- so one line in a policy file handed a
// confined agent the cloud metadata endpoint, and with it the IAM credentials
// of the machine it was running on. The policy documentation stated the
// opposite in as many words.
func TestPermitPrivateCannotReopenStructuralDenials(t *testing.T) {
	refused := []struct {
		cidr string
		why  string
	}{
		{"169.254.169.0/24", "the IMDS address itself"},
		{"169.254.0.0/16", "all of IPv4 link-local"},
		{"169.254.169.254/32", "a single-address exemption for IMDS"},
		{"169.253.0.0/15", "a prefix that straddles the edge of link-local space"},
		{"fe80::/64", "IPv6 link-local"},
		{"fd00:ec2::/64", "the AWS IPv6 metadata address"},
		{"100.64.0.0/24", "carrier-grade NAT, used for cloud internal routing"},
		{"64:ff9b::/96", "NAT64, which embeds an IPv4 address including IMDS"},
		{"224.0.0.0/24", "multicast"},
	}

	for _, tc := range refused {
		t.Run(tc.cidr, func(t *testing.T) {
			g, err := NewGuard([]string{tc.cidr})
			if err == nil {
				// Report what the acceptance actually costs, not just that a
				// constructor returned nil.
				if probe := g.Check(netip.MustParseAddr("169.254.169.254")); probe == nil {
					t.Fatalf("permit_private %q (%s) was accepted AND makes the metadata "+
						"endpoint reachable", tc.cidr, tc.why)
				}
				t.Fatalf("permit_private %q (%s) was accepted; it must be refused because "+
					"exemptions are consulted before the structural denials", tc.cidr, tc.why)
			}
			// Either refusal is correct. A wide prefix is caught by the
			// width check first, a narrow one by the overlap check; what
			// matters is that the operator is told which rule they hit.
			msg := err.Error()
			if !strings.Contains(msg, "never be exempted") && !strings.Contains(msg, "too broad") {
				t.Errorf("refused, but the message does not explain why: %v", err)
			}
		})
	}
}

// TestPermitPrivateStillAllowsLegitimateExemptions guards the other direction.
// Reaching a sidecar or an internal service is what permit_private is for, and
// refusing those would push operators towards turning the guard off entirely.
func TestPermitPrivateStillAllowsLegitimateExemptions(t *testing.T) {
	allowed := []struct {
		cidr, probe string
	}{
		{"127.0.0.0/24", "127.0.0.1"},
		{"10.4.2.0/24", "10.4.2.9"},
		{"192.168.50.0/24", "192.168.50.3"},
		{"172.31.99.0/24", "172.31.99.30"},
	}

	for _, tc := range allowed {
		t.Run(tc.cidr, func(t *testing.T) {
			g, err := NewGuard([]string{tc.cidr})
			if err != nil {
				t.Fatalf("permit_private %q is a legitimate narrow exemption but was refused: %v",
					tc.cidr, err)
			}
			if err := g.Check(netip.MustParseAddr(tc.probe)); err != nil {
				t.Fatalf("%s is inside the exemption but was refused: %v", tc.probe, err)
			}
			// The exemption must not leak beyond itself.
			if err := g.Check(netip.MustParseAddr("169.254.169.254")); err == nil {
				t.Fatal("exempting one subnet also reopened the metadata endpoint")
			}
		})
	}
}
