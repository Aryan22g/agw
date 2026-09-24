// Package confine implements non-cooperative egress containment.
//
// A gateway authorizes requests an agent chooses to send through it. This
// package handles the case the 2026 frontier lab
// incidents actually exercised: an agent that has root inside its own sandbox
// and does not want to cooperate. Enforcement therefore has to sit outside
// anything the agent controls, and the agent must have no route to the network
// except through it.

package confine

import (
	"errors"
	"fmt"
	"net/netip"
)

// Structural denials. These are not policy: no allowlist entry can permit
// them, because every one of them is a path out of the containment boundary
// rather than a destination beyond it.
//
// 169.254.169.254 is the cloud instance metadata endpoint. It is the single
// address that mattered most in the July 2026 Hugging Face intrusion -- the
// agent read AWS IAM credentials from it after gaining code execution. It sits
// in link-local space, which is why link-local is denied wholesale rather than
// by listing the one address.
var (
	ErrLoopback     = errors.New("confine: destination is loopback")
	ErrPrivate      = errors.New("confine: destination is a private address")
	ErrLinkLocal    = errors.New("confine: destination is link-local (cloud metadata lives here)")
	ErrUnspecified  = errors.New("confine: destination is the unspecified address")
	ErrMulticast    = errors.New("confine: destination is multicast")
	ErrCarrierNAT   = errors.New("confine: destination is in carrier-grade NAT space")
	ErrNAT64        = errors.New("confine: destination is a NAT64-mapped address")
	ErrNotPermitted = errors.New("confine: destination is not permitted by policy")
)

// Prefixes that Go's own classification helpers do not cover but which are
// reachable paths into infrastructure the agent should not touch.
var (
	// 100.64.0.0/10 -- RFC 6598. Used by cloud providers for internal
	// routing; not covered by IsPrivate.
	cgnat4 = netip.MustParsePrefix("100.64.0.0/10")

	// 64:ff9b::/96 -- RFC 6052 well-known NAT64 prefix. An address in here
	// embeds an IPv4 address in its low 32 bits, so it is a way to reach
	// 169.254.169.254 over IPv6 if treated as an ordinary global address.
	nat64 = netip.MustParsePrefix("64:ff9b::/96")

	// 64:ff9b:1::/48 -- RFC 8215 local-use NAT64 range.
	nat64Local = netip.MustParsePrefix("64:ff9b:1::/48")

	// AWS serves instance metadata over IPv6 at fd00:ec2::254. It sits inside
	// unique-local space, so IsPrivate already refuses it -- but as
	// ErrPrivate, which reads as an internal pivot rather than as a probe for
	// cloud credentials. Naming it keeps the metadata_endpoint reason code
	// meaning the same thing on both address families.
	metadata6 = netip.MustParseAddr("fd00:ec2::254")
)

// Guard classifies destination addresses. It answers one question: may this
// address be dialed at all, irrespective of what any policy says.
//
// A deployment that genuinely needs to reach a private address declares the
// exact prefix. There is deliberately no wildcard: the whole value of the
// structural denial is that it cannot be switched off in one line, which is
// how "no agent may reach the metadata endpoint" survives a later, more
// generous policy written by someone in a hurry.
type Guard struct {
	permitted []netip.Prefix
}

// neverExempt lists the address space no permit_private entry may reopen.
//
// The width check below is not enough on its own. 169.254.169.0/24 is a /24 --
// narrow enough to look like a considered exception -- and exemptions are
// consulted BEFORE every structural denial in Check, so that one line silently
// hands a confined agent the cloud metadata endpoint and the IAM credentials
// behind it. The gym found this by writing the policy an operator in a hurry
// would write and seeing what happened.
//
// Loopback and private space are deliberately absent from this list: reaching
// a sidecar or an internal service is the legitimate use of permit_private,
// and refusing it would push operators towards turning the guard off entirely.
// What is listed here is not "dangerous destinations" but "paths out of the
// containment boundary", which is a different and much shorter list.
var neverExempt = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"), // IPv4 link-local: IMDS lives here
	netip.MustParsePrefix("fe80::/10"),      // IPv6 link-local
	netip.MustParsePrefix("224.0.0.0/4"),    // IPv4 multicast
	netip.MustParsePrefix("ff00::/8"),       // IPv6 multicast
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT: cloud internal routing
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64: embeds an IPv4 address, including IMDS
	netip.MustParsePrefix("64:ff9b:1::/48"), // NAT64 local-use
	netip.MustParsePrefix("fd00:ec2::/64"),  // AWS IPv6 metadata, inside unique-local space
}

// NewGuard builds a guard. Each entry in permitPrivate is an explicit CIDR
// that is exempted from the structural denials.
//
// A prefix broad enough to be a wildcard is refused: exempting 0.0.0.0/0 or
// 10.0.0.0/8 is not a considered exception, it is turning the control off.
// A prefix that overlaps neverExempt is refused whatever its width, because
// the point of a structural denial is that policy cannot switch it off.
func NewGuard(permitPrivate []string) (*Guard, error) {
	g := &Guard{}

	for _, raw := range permitPrivate {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("confine: permit_private %q: %w", raw, err)
		}

		// Overlap, not containment: an exemption that merely INTERSECTS
		// link-local space still reopens part of it, and a /15 straddling
		// 169.254.0.0/16 would pass a containment test while covering half
		// the range.
		for _, banned := range neverExempt {
			if prefixesOverlap(p.Masked(), banned) {
				return nil, fmt.Errorf(
					"confine: permit_private %q overlaps %s, which can never be exempted: "+
						"this is the space the structural denials exist to protect",
					raw, banned)
			}
		}

		// Require a genuinely narrow exception. /24 for IPv4 is 256 hosts,
		// which is a subnet someone can reason about; /8 is not.
		minBits := 24
		if p.Addr().Is6() {
			minBits = 64
		}
		if p.Bits() < minBits {
			return nil, fmt.Errorf(
				"confine: permit_private %q is too broad (minimum /%d): name the subnet, not the internet",
				raw, minBits)
		}

		g.permitted = append(g.permitted, p.Masked())
	}

	return g, nil
}

// Check reports why an address may not be dialed, or nil if it may.
//
// The address is unmapped first. Without that, ::ffff:169.254.169.254 is an
// IPv6 address whose IPv4 classification helpers all return false, and the
// metadata endpoint becomes reachable through a four-character prefix.
func (g *Guard) Check(addr netip.Addr) error {
	if !addr.IsValid() {
		return fmt.Errorf("%w: invalid address", ErrUnspecified)
	}

	addr = addr.Unmap()

	// An explicit exemption wins over the structural denials -- that is what
	// it is for -- but it is checked against the unmapped address so the
	// exemption cannot be reached by a mapped spelling either.
	for _, p := range g.permitted {
		if p.Contains(addr) {
			return nil
		}
	}

	switch {
	case addr.IsLoopback():
		return ErrLoopback

	// Multicast is classified before link-local because ff02::1 and
	// 224.0.0.1 are both, and "multicast" is the more precise reason of the
	// two. Ordering it this way also keeps the metadata_endpoint reason code
	// reserved for link-local UNICAST, which is where metadata endpoints
	// actually live -- an operator grepping the evidence for that code should
	// find credential-endpoint probes, not routine multicast noise.
	case addr.IsMulticast(), addr.IsInterfaceLocalMulticast():
		return ErrMulticast
	case addr == metadata6:
		return ErrLinkLocal
	case addr.IsLinkLocalUnicast():
		return ErrLinkLocal
	case addr.IsUnspecified():
		return ErrUnspecified
	case addr.IsPrivate():
		return ErrPrivate
	case cgnat4.Contains(addr):
		return ErrCarrierNAT
	case nat64.Contains(addr), nat64Local.Contains(addr):
		// Rather than decode the embedded IPv4 and classify it, refuse the
		// whole range. A NAT64 destination is never something a confined
		// agent has a legitimate reason to reach directly, and decoding it
		// would mean maintaining a second classification path that has to
		// stay in agreement with the first one.
		return ErrNAT64
	}

	return nil
}

// prefixesOverlap reports whether two prefixes share any address. Two prefixes
// overlap exactly when one contains the other's base address, which is cheaper
// and less error-prone than comparing ranges.
func prefixesOverlap(a, b netip.Prefix) bool {
	return a.Contains(b.Masked().Addr()) || b.Contains(a.Masked().Addr())
}

// Reason maps a guard error to the stable reason code that goes into the
// evidence record. Callers must not derive reason codes from error strings.
func Reason(err error) string {
	switch {
	case err == nil:
		return "allowed"
	case errors.Is(err, ErrLinkLocal):
		return "metadata_endpoint"
	case errors.Is(err, ErrLoopback):
		return "loopback_denied"
	case errors.Is(err, ErrPrivate):
		return "private_address_denied"
	case errors.Is(err, ErrCarrierNAT):
		return "carrier_nat_denied"
	case errors.Is(err, ErrNAT64):
		return "nat64_denied"
	case errors.Is(err, ErrMulticast):
		return "multicast_denied"
	case errors.Is(err, ErrUnspecified):
		return "invalid_destination"
	case errors.Is(err, ErrNotPermitted):
		return "not_in_allowlist"
	default:
		return "denied"
	}
}
