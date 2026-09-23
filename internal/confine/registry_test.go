package confine

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeConn struct {
	closed atomic.Bool
}

func (c *fakeConn) Close() error { c.closed.Store(true); return nil }

func newRegistryWith(t *testing.T, id, addr string) *Registry {
	t.Helper()
	r := NewRegistry()
	if err := r.Register(Identity{
		WorkloadID:  id,
		TenantID:    "tenant-alpha",
		SourceAddr:  netip.MustParseAddr(addr),
		ImageDigest: "sha256:deadbeef",
		Command:     "python harness.py",
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	return r
}

func TestUnregisteredSourceGetsNoIdentity(t *testing.T) {
	r := newRegistryWith(t, "agent-01", "172.28.0.5")

	_, err := r.Lookup(netip.MustParseAddr("172.28.0.99"))
	if err == nil {
		t.Fatal("an unregistered address was given an identity")
	}
	if !errors.Is(err, ErrUnknownWorkload) {
		t.Errorf("got %v, want ErrUnknownWorkload", err)
	}
}

func TestAddressCannotBeRebound(t *testing.T) {
	r := newRegistryWith(t, "agent-01", "172.28.0.5")

	err := r.Register(Identity{
		WorkloadID: "agent-02",
		SourceAddr: netip.MustParseAddr("172.28.0.5"),
	})
	if err == nil {
		t.Fatal("a second workload took over an address already bound")
	}
}

func TestDuplicateWorkloadIsRefused(t *testing.T) {
	r := newRegistryWith(t, "agent-01", "172.28.0.5")

	err := r.Register(Identity{
		WorkloadID: "agent-01",
		SourceAddr: netip.MustParseAddr("172.28.0.6"),
	})
	if err == nil {
		t.Fatal("the same workload id was registered twice")
	}
}

func TestMappedAddressResolvesToTheSameWorkload(t *testing.T) {
	r := newRegistryWith(t, "agent-01", "172.28.0.5")

	id, err := r.Lookup(netip.MustParseAddr("::ffff:172.28.0.5"))
	if err != nil {
		t.Fatalf("mapped form of a registered address was not found: %v", err)
	}
	if id.WorkloadID != "agent-01" {
		t.Errorf("workload = %q, want agent-01", id.WorkloadID)
	}
}

// TestRevokeClosesLiveConnections is the kill-switch property: it must not
// only refuse the next connection, it must end the ones already running.
func TestRevokeClosesLiveConnections(t *testing.T) {
	r := newRegistryWith(t, "agent-01", "172.28.0.5")

	conns := make([]*fakeConn, 5)
	for i := range conns {
		conns[i] = &fakeConn{}
		if _, err := r.Track("agent-01", conns[i]); err != nil {
			t.Fatalf("track: %v", err)
		}
	}

	if got := r.LiveConnections("agent-01"); got != 5 {
		t.Fatalf("live connections = %d, want 5", got)
	}

	res, err := r.Revoke("agent-01", "anomalous egress volume")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res.ConnectionsClosed != 5 {
		t.Errorf("closed %d connections, want 5", res.ConnectionsClosed)
	}
	for i, c := range conns {
		if !c.closed.Load() {
			t.Errorf("connection %d was left open after revocation", i)
		}
	}
}

func TestRevokedWorkloadIsRefusedEverywhere(t *testing.T) {
	r := newRegistryWith(t, "agent-01", "172.28.0.5")

	if _, err := r.Revoke("agent-01", "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	if _, err := r.Lookup(netip.MustParseAddr("172.28.0.5")); !errors.Is(err, ErrRevoked) {
		t.Errorf("Lookup after revoke: got %v, want ErrRevoked", err)
	}
	if _, err := r.Track("agent-01", &fakeConn{}); !errors.Is(err, ErrRevoked) {
		t.Errorf("Track after revoke: got %v, want ErrRevoked", err)
	}
	if revoked, reason := r.IsRevoked("agent-01"); !revoked || reason != "test" {
		t.Errorf("IsRevoked = %v, %q", revoked, reason)
	}
}

// TestRevokeRacesAgainstNewConnections is the race the lock ordering exists
// to close: a connection established while revocation is in flight must not
// survive it.
func TestRevokeRacesAgainstNewConnections(t *testing.T) {
	for attempt := 0; attempt < 50; attempt++ {
		r := newRegistryWith(t, "agent-01", "172.28.0.5")

		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			accepted []*fakeConn
		)

		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				c := &fakeConn{}
				if _, err := r.Track("agent-01", c); err == nil {
					mu.Lock()
					accepted = append(accepted, c)
					mu.Unlock()
				}
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = r.Revoke("agent-01", "race")
		}()

		wg.Wait()

		// Every connection that was accepted must now be closed. If Track
		// could slip in after the flag was set, one would still be open.
		mu.Lock()
		for i, c := range accepted {
			if !c.closed.Load() {
				t.Fatalf("attempt %d: connection %d survived revocation", attempt, i)
			}
		}
		mu.Unlock()

		if n := r.LiveConnections("agent-01"); n != 0 {
			t.Fatalf("attempt %d: %d connections still tracked after revocation", attempt, n)
		}
	}
}

func TestRevokeIsIdempotent(t *testing.T) {
	r := newRegistryWith(t, "agent-01", "172.28.0.5")

	first, err := r.Revoke("agent-01", "one")
	if err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	second, err := r.Revoke("agent-01", "two")
	if err != nil {
		t.Fatalf("second revoke: %v", err)
	}
	if !second.At.Equal(first.At) {
		t.Error("a second revocation changed the recorded revocation time")
	}
}

func TestReleaseStopsTracking(t *testing.T) {
	r := newRegistryWith(t, "agent-01", "172.28.0.5")

	c := &fakeConn{}
	release, err := r.Track("agent-01", c)
	if err != nil {
		t.Fatalf("track: %v", err)
	}
	if r.LiveConnections("agent-01") != 1 {
		t.Fatal("connection was not tracked")
	}

	release()

	if n := r.LiveConnections("agent-01"); n != 0 {
		t.Errorf("live connections = %d after release, want 0", n)
	}
}

func TestKillSwitchLatencyIsBounded(t *testing.T) {
	r := newRegistryWith(t, "agent-01", "172.28.0.5")

	for i := 0; i < 500; i++ {
		if _, err := r.Track("agent-01", &fakeConn{}); err != nil {
			t.Fatalf("track: %v", err)
		}
	}

	res, err := r.Revoke("agent-01", "load")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if res.ConnectionsClosed != 500 {
		t.Errorf("closed %d, want 500", res.ConnectionsClosed)
	}
	// The product claim is sub-100ms. In-process teardown should be orders of
	// magnitude under that; this asserts the claim rather than describing it.
	if res.Latency > 100*time.Millisecond {
		t.Errorf("revocation took %v, want < 100ms", res.Latency)
	}
	t.Logf("revoked 500 connections in %v", res.Latency)
}
