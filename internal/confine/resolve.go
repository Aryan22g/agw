package confine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// Resolver turns a destination into a connection, refusing anything the Guard
// rejects.
//
// The important property is that it resolves ONCE and dials the exact address
// it validated. The obvious implementation -- resolve, check the results, then
// hand the original host:port to a dialer -- re-resolves inside the dialer and
// is exploitable: an attacker controlling DNS for a permitted hostname can
// answer with a public address for the check and a private one for the dial.
// DNS rebinding is cheap, and the whole point of the guard is the addresses it
// refuses.
//
// If another path ever needs to dial a name supplied from outside, it belongs
// here rather than reimplemented alongside.
type Resolver struct {
	guard         *Guard
	lookup        LookupFunc
	dialer        *net.Dialer
	lookupTimeout time.Duration
}

// LookupFunc resolves a hostname to addresses. Injectable so the rebinding
// defence can be tested precisely: a control whose failure mode cannot be
// reproduced in a test is a control nobody knows works.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// ResolverConfig configures a Resolver.
type ResolverConfig struct {
	Guard *Guard

	// DialTimeout bounds a single connection attempt.
	DialTimeout time.Duration

	// LookupTimeout bounds name resolution.
	LookupTimeout time.Duration

	// Lookup overrides name resolution. Defaults to the system resolver;
	// in production that is correct, because the containment boundary is the
	// network, not the name service.
	Lookup LookupFunc
}

// NewResolver builds a Resolver.
func NewResolver(cfg ResolverConfig) (*Resolver, error) {
	if cfg.Guard == nil {
		return nil, errors.New("confine: resolver requires a guard")
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.LookupTimeout <= 0 {
		cfg.LookupTimeout = 5 * time.Second
	}
	lookup := cfg.Lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}

	return &Resolver{
		guard:         cfg.Guard,
		lookup:        lookup,
		dialer:        &net.Dialer{Timeout: cfg.DialTimeout},
		lookupTimeout: cfg.LookupTimeout,
	}, nil
}

// Resolve returns the addresses a host maps to, with every one of them
// checked against the guard.
//
// If ANY resolved address is refused, the whole destination is refused rather
// than falling back to the addresses that passed. A hostname that resolves to
// both a public address and the metadata endpoint is not a hostname with one
// bad answer; it is a hostname under someone else's control.
func (r *Resolver) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	// An IP literal needs no resolution -- and must not be handed to the
	// resolver, which would happily look up "169.254.169.254" as a name on
	// some configurations.
	if addr, err := netip.ParseAddr(host); err == nil {
		if err := r.guard.Check(addr); err != nil {
			return nil, err
		}
		return []netip.Addr{addr.Unmap()}, nil
	}

	ctx, cancel := context.WithTimeout(ctx, r.lookupTimeout)
	defer cancel()

	ips, err := r.lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("confine: resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("confine: %s resolved to no addresses", host)
	}

	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		ip = ip.Unmap()
		if err := r.guard.Check(ip); err != nil {
			return nil, fmt.Errorf("%w (%s resolves to %s)", err, host, ip)
		}
		out = append(out, ip)
	}

	return out, nil
}

// Dial connects to host:port, refusing anything the guard rejects.
//
// Every address is validated before any is dialed, and the dial targets the
// validated address directly, so no second resolution can occur between the
// check and the connection.
func (r *Resolver) Dial(ctx context.Context, host string, port int) (net.Conn, error) {
	addrs, err := r.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, a := range addrs {
		ap := netip.AddrPortFrom(a, uint16(port))

		// Dialing the literal address string rather than the hostname is the
		// entire point: net.Dialer will not re-resolve an IP literal.
		conn, err := r.dialer.DialContext(ctx, tcpNetwork(a), ap.String())
		if err != nil {
			lastErr = err
			continue
		}
		return conn, nil
	}

	return nil, fmt.Errorf("confine: could not connect to %s:%d: %w", host, port, lastErr)
}

func tcpNetwork(a netip.Addr) string {
	if a.Is4() {
		return "tcp4"
	}
	return "tcp6"
}
