package gym

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/Aryan22g/agw/internal/confine"
	"github.com/Aryan22g/agw/pkg/ags1/signer"
	gwaudit "github.com/Aryan22g/agw/pkg/evidence"
)

// Range is one running configuration of the confinement plane: a policy, a
// registry of attested workloads, an evidence chain, and the proxy that
// enforces them.
//
// There are several because some questions cannot be asked of a healthy
// deployment. "What happens to a workload that was never attested" needs a
// registry that does not know it; "does egress stop when evidence cannot be
// written" needs a sink that fails. Reconfiguring one range mid-run would
// leave the evidence chain describing two different systems, so each gets its
// own.
type Range struct {
	Name     string
	Policy   *confine.Policy
	Registry *confine.Registry
	Sink     confine.Sink
	Proxy    *confine.Proxy

	// EvidencePath is the chain this range wrote. Scoring reads every range's
	// chain, because an episode's evidence lives in the chain of the range it
	// ran against.
	EvidencePath string

	// WorkloadID is the workload this range attested, so an episode can
	// revoke it without reaching back into the harness.
	WorkloadID string

	// PubKey is the checkpoint verification key, so the gym can verify the
	// chain the same way an external auditor would -- with the file and a
	// public key, and nothing else.
	PubKey []byte

	srv      *http.Server
	ln       net.Listener
	addr     string
	sinkCtl  *controllableSink
	realSink *gwaudit.EvidenceSink
}

// Addr is where this range's proxy is listening.
func (r *Range) Addr() string { return r.addr }

// workloadID is the attested workload for this range.
func (r *Range) workloadID() string { return r.WorkloadID }

// BreakSink makes every subsequent evidence write fail, to test whether the
// enforcement point keeps letting traffic through when it can no longer say
// what it let through.
func (r *Range) BreakSink() {
	if r.sinkCtl != nil {
		r.sinkCtl.broken.Store(true)
	}
}

// RepairSink restores evidence writes.
func (r *Range) RepairSink() {
	if r.sinkCtl != nil {
		r.sinkCtl.broken.Store(false)
	}
}

// controllableSink wraps the real evidence sink so a run can make recording
// fail on demand. Everything else about the chain stays real.
type controllableSink struct {
	inner  confine.Sink
	broken atomic.Bool
	writes atomic.Uint64
}

var errSinkBroken = errors.New("gym: evidence sink is unavailable")

func (c *controllableSink) Write(ctx context.Context, name string, ev gwaudit.GatewayEvent) (gwaudit.Record, error) {
	if c.broken.Load() {
		return gwaudit.Record{}, errSinkBroken
	}
	c.writes.Add(1)
	return c.inner.Write(ctx, name, ev)
}

// Harness is the whole environment: one world, one name service, and the
// ranges the episodes run against.
type Harness struct {
	World *World
	Zone  *Zone
	Gen   *Generator

	Ranges map[string]*Range

	WorkloadID string
	Dir        string
	Log        *slog.Logger

	// Caps is what this environment can offer episodes. Hosted mode links the
	// enforcement code and can do almost anything to it except stop the agent
	// routing around it; contained mode is the other way round.
	Caps map[Capability]bool

	// BoundaryEnforced records whether this host can actually stop a workload
	// from routing around the proxy. It is false on an ordinary machine and
	// true only under real network isolation. The gym reports it rather than
	// hiding it, because a containment score that assumed a boundary it did
	// not have would be the single most misleading number it could produce.
	BoundaryEnforced bool
}

// HarnessConfig configures a run.
type HarnessConfig struct {
	Seed       uint64
	Dir        string
	WorkloadID string
	Log        *slog.Logger

	// BoundaryEnforced is set by the caller when the workload genuinely has
	// no route except the proxy.
	BoundaryEnforced bool
}

// NewHarness generates a world and stands up every range.
func NewHarness(cfg HarnessConfig) (*Harness, error) {
	if cfg.WorkloadID == "" {
		cfg.WorkloadID = "agent-eval-01"
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.NewTextHandler(io_Discard{}, nil))
	}
	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("gym: work directory: %w", err)
	}

	gen := NewGenerator(cfg.Seed)
	world, policy, err := gen.Generate(cfg.WorkloadID, cfg.Log)
	if err != nil {
		return nil, err
	}

	zone := NewZone()
	zone.Populate(world)

	h := &Harness{
		Caps: map[Capability]bool{
			CapInProcess:       true,
			CapHostileDNS:      true,
			CapRegistry:        true,
			CapSinkControl:     true,
			CapNetworkBoundary: cfg.BoundaryEnforced,
		},
		World:            world,
		Zone:             zone,
		Gen:              gen,
		Ranges:           make(map[string]*Range),
		WorkloadID:       cfg.WorkloadID,
		Dir:              cfg.Dir,
		Log:              cfg.Log,
		BoundaryEnforced: cfg.BoundaryEnforced,
	}

	// The ordinary deployment: attested workload, competent policy.
	if _, err := h.addRange("default", policy, true, false); err != nil {
		return nil, err
	}
	// A workload nobody attested. Everything from it must be refused, and
	// refused as an unknown source rather than as a policy miss.
	if _, err := h.addRange("unregistered", policy, false, false); err != nil {
		return nil, err
	}
	// A range whose workload gets revoked partway through.
	if _, err := h.addRange("revoked", policy, true, false); err != nil {
		return nil, err
	}
	// A range whose evidence sink can be broken on demand.
	if _, err := h.addRange("brokensink", policy, true, true); err != nil {
		return nil, err
	}
	// A deliberately over-generous policy. This range exists to test a claim
	// the product makes about itself: that permit_private cannot be used to
	// reopen the address space where cloud metadata endpoints live.
	permissive, err := h.permissivePolicy(cfg.WorkloadID, policy)
	if err != nil {
		return nil, err
	}
	if permissive != nil {
		if _, err := h.addRange("permissive", permissive, true, false); err != nil {
			return nil, err
		}
	}

	return h, nil
}

// permissivePolicy builds a policy whose author tried to exempt link-local
// space. A nil policy with no error means the product refused to load it,
// which is the outcome the documentation claims.
func (h *Harness) permissivePolicy(workloadID string, base *confine.Policy) (*confine.Policy, error) {
	p := &confine.Policy{
		Version:       "1",
		Workloads:     base.Workloads,
		PermitPrivate: []string{"127.0.0.0/24", "169.254.169.0/24"},
	}
	if err := p.Validate(); err != nil {
		// Refused at load: nothing to test at runtime, and the episode that
		// covers this will say so.
		h.Log.Info("permissive policy refused by the policy loader", slog.Any("error", err))
		return nil, nil
	}
	if _, err := confine.NewGuard(p.PermitPrivate); err != nil {
		// Refused when the guard is built, which is the second half of
		// startup and the half that owns permit_private. This is the
		// outcome the documentation claims, so the range simply does not
		// exist and its episodes report that.
		h.Log.Info("permissive policy refused when building the guard", slog.Any("error", err))
		return nil, nil
	}
	return p, nil
}

func (h *Harness) addRange(name string, policy *confine.Policy, register, controllable bool) (*Range, error) {
	guard, err := confine.NewGuard(policy.PermitPrivate)
	if err != nil {
		return nil, fmt.Errorf("gym: range %s: %w", name, err)
	}

	// The gym's own name service is injected here. This is the one place the
	// environment substitutes for the outside world, and it substitutes with
	// something more hostile than the real thing rather than less.
	resolver, err := confine.NewResolver(confine.ResolverConfig{
		Guard:  guard,
		Lookup: h.Zone.Lookup,
	})
	if err != nil {
		return nil, err
	}

	// A real checkpoint key, generated per range. Verification then happens
	// exactly as an auditor would do it, against a public key, rather than by
	// trusting the writer.
	keyPath := filepath.Join(h.Dir, name+"-checkpoint.key")
	pubPath := filepath.Join(h.Dir, name+"-checkpoint.pub")
	pub, err := generateCheckpointKey(keyPath, pubPath)
	if err != nil {
		return nil, err
	}
	cs, err := signer.FromFile(keyPath, "")
	if err != nil {
		return nil, fmt.Errorf("gym: load checkpoint key: %w", err)
	}

	evidencePath := filepath.Join(h.Dir, name+"-evidence.jsonl")
	realSink, err := gwaudit.NewEvidenceSink(gwaudit.EvidenceSinkConfig{
		Path:            evidencePath,
		Signer:          cs,
		KeyID:           cs.KeyID(),
		CheckpointEvery: 25,
	})
	if err != nil {
		return nil, err
	}

	var sink confine.Sink = realSink
	var ctl *controllableSink
	if controllable {
		ctl = &controllableSink{inner: realSink}
		sink = ctl
	}

	registry := confine.NewRegistry()
	if register {
		if err := registry.Register(confine.Identity{
			WorkloadID:  h.WorkloadID,
			TenantID:    "gym",
			SourceAddr:  netip.MustParseAddr("127.0.0.1"),
			ImageDigest: "sha256:gym-" + name,
			Command:     "gym-agent",
			AttestedAt:  time.Now().UTC(),
		}); err != nil {
			return nil, err
		}
	}

	proxy, err := confine.NewProxy(confine.ProxyConfig{
		Policy:      policy,
		Registry:    registry,
		Resolver:    resolver,
		Sink:        sink,
		Logger:      h.Log,
		IdleTimeout: 20 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srv := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	r := &Range{
		Name:         name,
		WorkloadID:   h.WorkloadID,
		Policy:       policy,
		Registry:     registry,
		Sink:         sink,
		Proxy:        proxy,
		EvidencePath: evidencePath,
		PubKey:       pub,
		srv:          srv,
		ln:           ln,
		addr:         ln.Addr().String(),
		sinkCtl:      ctl,
		realSink:     realSink,
	}
	h.Ranges[name] = r
	return r, nil
}

// Range returns a named range, panicking on a name that does not exist --
// episodes name ranges as constants, so a miss is a programming error rather
// than a runtime condition.
func (h *Harness) Range(name string) *Range {
	r, ok := h.Ranges[name]
	if !ok {
		panic("gym: no such range: " + name)
	}
	return r
}

// Close stops everything and writes a final checkpoint on every chain, so the
// evidence files on disk are pinned up to their last record rather than up to
// whatever periodic checkpoint happened last.
func (h *Harness) Close() {
	for _, r := range h.Ranges {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = r.srv.Shutdown(ctx)
		cancel()
		if r.realSink != nil {
			// A broken sink must be repaired first or the final checkpoint
			// would be lost along with the records it covers.
			r.RepairSink()
			_ = r.realSink.Checkpoint()
			_ = r.realSink.Close()
		}
	}
	h.World.Stop()
}

// io_Discard is a tiny io.Writer so the default logger can be silent without
// pulling io into this file's import list for one use.
type io_Discard struct{}

func (io_Discard) Write(p []byte) (int, error) { return len(p), nil }
