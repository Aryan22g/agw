package gym

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
)

// Zone is the gym's name service.
//
// It exists so DNS can be made hostile on purpose. The confinement plane's
// central claim about name resolution is that it resolves once and dials the
// address it checked, which is only meaningful if something can answer
// differently the second time. A real resolver cannot be made to do that on
// demand; this one can, so the defence is measured rather than asserted.
type Zone struct {
	mu      sync.Mutex
	records map[string][]netip.Addr

	// rebind holds hostnames that answer differently on each lookup: the
	// first answer is benign, every later one points somewhere the guard must
	// refuse. This is DNS rebinding, reproduced exactly.
	rebind map[string]*rebinder

	lookups atomic.Uint64
}

type rebinder struct {
	first  []netip.Addr
	later  []netip.Addr
	served atomic.Uint64
}

// NewZone builds an empty zone.
func NewZone() *Zone {
	return &Zone{
		records: make(map[string][]netip.Addr),
		rebind:  make(map[string]*rebinder),
	}
}

// Add maps a hostname to one or more addresses.
func (z *Zone) Add(host string, addrs ...netip.Addr) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.records[canonHost(host)] = addrs
}

// AddRebinding makes a hostname answer with first on the first lookup and
// later on every lookup after that.
func (z *Zone) AddRebinding(host string, first, later []netip.Addr) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.rebind[canonHost(host)] = &rebinder{first: first, later: later}
}

// Lookups reports how many resolutions have been served, which is how an
// episode detects a second resolution happening where there should be one.
func (z *Zone) Lookups() uint64 { return z.lookups.Load() }

// Lookup satisfies confine.LookupFunc.
func (z *Zone) Lookup(_ context.Context, host string) ([]netip.Addr, error) {
	z.lookups.Add(1)
	h := canonHost(host)

	z.mu.Lock()
	rb := z.rebind[h]
	rec := z.records[h]
	z.mu.Unlock()

	if rb != nil {
		n := rb.served.Add(1)
		if n == 1 {
			return rb.first, nil
		}
		return rb.later, nil
	}
	if len(rec) > 0 {
		return rec, nil
	}
	return nil, fmt.Errorf("gym: NXDOMAIN for %q", host)
}

// Populate maps every world service to the loopback address it is bound to.
func (z *Zone) Populate(w *World) {
	lo := netip.MustParseAddr("127.0.0.1")
	for _, s := range w.Services {
		z.Add(s.Hostname, lo)
	}
}

// canonHost normalises a name the way a resolver would: case-insensitive, and
// the root dot is not part of the name.
//
// Doing this here is deliberate. If the zone were case-sensitive, a policy
// matching bug around case would be masked by a lookup failure, and the gym
// would report the wrong reason for the right outcome.
func canonHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}
