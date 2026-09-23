package confine

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"
)

var (
	// ErrUnknownWorkload is returned when a connection arrives from an
	// address no supervisor registered. It is not an identity lookup failure
	// to be retried -- it means something is on the confined network that was
	// not launched through us.
	ErrUnknownWorkload = errors.New("confine: no workload registered for source address")

	// ErrRevoked is returned once a workload has been killed.
	ErrRevoked = errors.New("confine: workload is revoked")
)

// Identity is what a supervisor attests about a workload when it launches it.
//
// This is identity by provenance: the workload presents nothing and holds no credential. Its identity is the
// network path its traffic arrives on, bound at launch to what was actually
// started there. An agent with root inside its sandbox cannot forge this,
// because it does not control the address assignment.
type Identity struct {
	WorkloadID string
	TenantID   string

	// SourceAddr is the address the workload's traffic will arrive from.
	// This is the binding: it is assigned by the supervisor, not chosen by
	// the workload.
	SourceAddr netip.Addr

	// What was launched. Recorded into every evidence entry so a reviewer can
	// tell which build of which agent took an action.
	ImageDigest string
	Command     string

	AttestedAt time.Time
}

type workloadState struct {
	identity Identity

	revoked       bool
	revokedReason string
	revokedAt     time.Time

	// Live connections, so revocation can close what is already open rather
	// than only refusing what comes next. A kill switch that lets existing
	// connections run to completion is not a kill switch.
	conns map[io.Closer]struct{}
}

// Registry maps source addresses to attested workloads, tracks their live
// connections, and revokes them.
type Registry struct {
	mu     sync.RWMutex
	byAddr map[netip.Addr]*workloadState
	byID   map[string]*workloadState
}

// NewRegistry builds an empty registry. A workload not registered here can
// reach nothing, which is the point: there is no default identity.
func NewRegistry() *Registry {
	return &Registry{
		byAddr: make(map[netip.Addr]*workloadState),
		byID:   make(map[string]*workloadState),
	}
}

// Register binds a source address to an attested workload.
func (r *Registry) Register(id Identity) error {
	if id.WorkloadID == "" {
		return errors.New("confine: workload id is required")
	}
	if !id.SourceAddr.IsValid() {
		return fmt.Errorf("confine: workload %q has no source address", id.WorkloadID)
	}
	if id.AttestedAt.IsZero() {
		id.AttestedAt = time.Now().UTC()
	}
	id.SourceAddr = id.SourceAddr.Unmap()

	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.byAddr[id.SourceAddr]; ok && existing.identity.WorkloadID != id.WorkloadID {
		// Two workloads claiming one address means the supervisor is
		// confused or something is spoofing. Either way, refusing is correct:
		// silently rebinding would let a second workload inherit the first
		// one's policy.
		return fmt.Errorf("confine: address %s is already bound to workload %q",
			id.SourceAddr, existing.identity.WorkloadID)
	}
	if _, ok := r.byID[id.WorkloadID]; ok {
		return fmt.Errorf("confine: workload %q is already registered", id.WorkloadID)
	}

	st := &workloadState{identity: id, conns: make(map[io.Closer]struct{})}
	r.byAddr[id.SourceAddr] = st
	r.byID[id.WorkloadID] = st
	return nil
}

// Lookup resolves a source address to its attested identity.
func (r *Registry) Lookup(addr netip.Addr) (Identity, error) {
	addr = addr.Unmap()

	r.mu.RLock()
	defer r.mu.RUnlock()

	st, ok := r.byAddr[addr]
	if !ok {
		return Identity{}, fmt.Errorf("%w: %s", ErrUnknownWorkload, addr)
	}
	if st.revoked {
		return st.identity, fmt.Errorf("%w: %s (%s)",
			ErrRevoked, st.identity.WorkloadID, st.revokedReason)
	}
	return st.identity, nil
}

// Track registers a live connection against a workload and returns a release
// function to call when it closes.
//
// Returns ErrRevoked if the workload was revoked before this connection was
// tracked. That check happens under the same lock that revocation takes, which
// closes the race where a connection is established between the revocation
// flag being set and the existing connections being closed.
func (r *Registry) Track(workloadID string, conn io.Closer) (release func(), err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	st, ok := r.byID[workloadID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownWorkload, workloadID)
	}
	if st.revoked {
		return nil, fmt.Errorf("%w: %s", ErrRevoked, workloadID)
	}

	st.conns[conn] = struct{}{}

	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		delete(st.conns, conn)
	}, nil
}

// RevokeResult reports what a revocation did. The latency is the product
// claim, so it is measured rather than asserted.
type RevokeResult struct {
	WorkloadID        string
	ConnectionsClosed int
	Latency           time.Duration
	At                time.Time
}

// Revoke kills a workload: new connections are refused and every live
// connection is closed.
//
// This does not ask the workload to stop. It is the control that has to work
// when the agent is actively hostile, which is the case the 2026 incidents
// established as the one that matters.
func (r *Registry) Revoke(workloadID, reason string) (RevokeResult, error) {
	start := time.Now()

	r.mu.Lock()

	st, ok := r.byID[workloadID]
	if !ok {
		r.mu.Unlock()
		return RevokeResult{}, fmt.Errorf("%w: %s", ErrUnknownWorkload, workloadID)
	}
	if st.revoked {
		r.mu.Unlock()
		return RevokeResult{WorkloadID: workloadID, At: st.revokedAt}, nil
	}

	// Set the flag first, inside the lock. From this instant Track refuses,
	// so no new connection can be added while we are closing the old ones.
	st.revoked = true
	st.revokedReason = reason
	st.revokedAt = time.Now().UTC()

	doomed := make([]io.Closer, 0, len(st.conns))
	for c := range st.conns {
		doomed = append(doomed, c)
	}
	st.conns = make(map[io.Closer]struct{})

	r.mu.Unlock()

	// Closing happens outside the lock: a Close that blocks must not stall
	// every other workload's traffic.
	for _, c := range doomed {
		_ = c.Close()
	}

	return RevokeResult{
		WorkloadID:        workloadID,
		ConnectionsClosed: len(doomed),
		Latency:           time.Since(start),
		At:                st.revokedAt,
	}, nil
}

// IsRevoked reports whether a workload has been killed, and why.
func (r *Registry) IsRevoked(workloadID string) (bool, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	st, ok := r.byID[workloadID]
	if !ok {
		return false, ""
	}
	return st.revoked, st.revokedReason
}

// LiveConnections reports how many connections a workload currently holds.
func (r *Registry) LiveConnections(workloadID string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	st, ok := r.byID[workloadID]
	if !ok {
		return 0
	}
	return len(st.conns)
}
