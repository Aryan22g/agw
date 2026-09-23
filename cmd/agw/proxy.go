package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Aryan22g/agw/internal/confine"
	gwaudit "github.com/Aryan22g/agw/internal/gateway/audit"
)

type workloadFlags []string

func (w *workloadFlags) String() string { return strings.Join(*w, ",") }
func (w *workloadFlags) Set(v string) error {
	*w = append(*w, v)
	return nil
}

func runProxy(args []string) error {
	fs := flagSet("proxy")
	var (
		policyPath   = fs.String("policy", "", "egress policy file")
		listen       = fs.String("listen", "0.0.0.0:8080", "address to accept confined traffic on")
		adminSocket  = fs.String("admin", "/var/run/agw/admin.sock", "unix socket for the control interface")
		evidencePath = fs.String("evidence", "", "evidence chain file (JSONL)")
		keyPath      = fs.String("key", "", "checkpoint key: a file, unix:SOCKET for ags-signd, or none (default: ~/.agw/checkpoint.key)")
		idleTimeout  = fs.Duration("idle-timeout", 5*time.Minute, "idle timeout for tunnelled connections")
		checkpointN  = fs.Uint64("checkpoint-every", 50, "write a signed checkpoint every N records")
		workloads    workloadFlags
	)
	fs.Var(&workloads, "workload", "attested workload as ID=SOURCE_ADDR (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" {
		return errors.New("--policy is required")
	}
	if *evidencePath == "" {
		return errors.New("--evidence is required")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	policy, err := confine.LoadPolicy(*policyPath)
	if err != nil {
		return err
	}

	guard, err := confine.NewGuard(policy.PermitPrivate)
	if err != nil {
		return err
	}

	resolver, err := confine.NewResolver(confine.ResolverConfig{Guard: guard})
	if err != nil {
		return err
	}

	sinkCfg := gwaudit.EvidenceSinkConfig{
		Path:               *evidencePath,
		CheckpointEvery:    *checkpointN,
		CheckpointInterval: agwCheckpointInterval,
	}
	ck, err := resolveCheckpointKey(*keyPath)
	if err != nil {
		return err
	}
	defer ck.Close()
	ck.apply(&sinkCfg)
	if ck.signer == nil {
		// Without a checkpoint key the chain is still internally consistent
		// and detects edits, but it cannot be pinned: someone able to rewrite
		// the whole file could recompute every hash into a consistent forgery.
		logger.Warn("no checkpoint key: the chain will detect edits but cannot be pinned against a full rewrite")
	} else {
		logger.Info("checkpoint signing enabled", slog.String("key_id", ck.keyID), slog.String("custody", ck.Source))
	}

	sink, err := gwaudit.NewEvidenceSink(sinkCfg)
	if err != nil {
		return err
	}
	defer sink.Close()

	registry := confine.NewRegistry()
	for _, spec := range workloads {
		id, addrStr, ok := strings.Cut(spec, "=")
		if !ok {
			return fmt.Errorf("--workload %q: expected ID=SOURCE_ADDR", spec)
		}
		addr, err := netip.ParseAddr(strings.TrimSpace(addrStr))
		if err != nil {
			return fmt.Errorf("--workload %q: %w", spec, err)
		}
		ident := confine.Identity{
			WorkloadID:  strings.TrimSpace(id),
			TenantID:    "local",
			SourceAddr:  addr,
			ImageDigest: os.Getenv("AGW_WORKLOAD_IMAGE"),
			Command:     os.Getenv("AGW_WORKLOAD_COMMAND"),
			AttestedAt:  time.Now().UTC(),
		}
		if err := registry.Register(ident); err != nil {
			return err
		}
		if _, err := sink.Write(context.Background(), confine.EventWorkloadRegistered, gwaudit.GatewayEvent{
			TenantID:   ident.TenantID,
			AgentID:    ident.WorkloadID,
			KeyID:      ident.ImageDigest,
			Action:     "workload.register",
			ResourceID: addr.String(),
			Decision:   "allow",
			ReasonCode: "attested",
			StartedAt:  ident.AttestedAt,
			FinishedAt: ident.AttestedAt,
		}); err != nil {
			return fmt.Errorf("record workload registration: %w", err)
		}
		logger.Info("workload registered",
			slog.String("workload", ident.WorkloadID), slog.String("source", addr.String()))
	}

	proxy, err := confine.NewProxy(confine.ProxyConfig{
		Policy:      policy,
		Registry:    registry,
		Resolver:    resolver,
		Sink:        sink,
		Logger:      logger,
		IdleTimeout: *idleTimeout,
	})
	if err != nil {
		return err
	}

	// The control interface is a unix socket rather than a port. A confined
	// workload that could reach the endpoint able to revoke it would be able
	// to probe -- or disable -- its own kill switch.
	adminSrv, adminLn, err := startAdmin(*adminSocket, proxy, registry, sink, logger, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = adminSrv.Close()
		_ = adminLn.Close()
		_ = os.Remove(*adminSocket)
	}()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           proxy,
		ReadHeaderTimeout: 15 * time.Second,
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}

	logger.Info("confinement proxy listening",
		slog.String("listen", *listen),
		slog.String("admin", *adminSocket),
		slog.String("evidence", *evidencePath),
		slog.Int("workloads", len(workloads)))

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case <-stop:
		logger.Info("shutting down")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)

	// A final checkpoint means the chain is pinned up to the last record
	// written, rather than ending at whatever the last periodic checkpoint
	// happened to cover.
	if err := sink.Checkpoint(); err != nil {
		logger.Error("final checkpoint failed", slog.Any("error", err))
	}

	allowed, denied := proxy.Stats()
	logger.Info("stopped", slog.Uint64("allowed", allowed), slog.Uint64("denied", denied))
	return nil
}

// startAdmin serves the control interface on a unix socket.
//
// onRevoke, if set, runs after the registry has cut the workload's
// connections -- `agw run` uses it to kill the workload itself, the third
// level of the kill switch.
func startAdmin(path string, proxy *confine.Proxy, registry *confine.Registry, sink *gwaudit.EvidenceSink,
	logger *slog.Logger, onRevoke func(workload string) string) (*http.Server, net.Listener, error) {
	if err := os.MkdirAll(dirOf(path), 0o750); err != nil {
		return nil, nil, fmt.Errorf("admin socket directory: %w", err)
	}
	// A socket file that still answers belongs to another running agw.
	// Removing it -- what this used to do unconditionally -- would silently
	// take over that process's kill switch, and `agw suspend` would then
	// reach the wrong enforcement point.
	if c, err := net.DialTimeout("unix", path, 300*time.Millisecond); err == nil {
		_ = c.Close()
		return nil, nil, fmt.Errorf("admin socket %s is in use by another agw; pass --admin with a different path", path)
	}
	_ = os.Remove(path)

	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, nil, fmt.Errorf("admin socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, nil, fmt.Errorf("admin socket mode: %w", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("POST /revoke", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Workload string `json:"workload"`
			Reason   string `json:"reason"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, "malformed request", http.StatusBadRequest)
			return
		}
		if req.Reason == "" {
			req.Reason = "revoked by operator"
		}

		res, err := registry.Revoke(req.Workload, req.Reason)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		killed := ""
		if onRevoke != nil {
			killed = onRevoke(res.WorkloadID)
		}

		// The kill switch firing is itself an audit event, in the same chain
		// as the traffic that prompted it.
		if _, err := sink.Write(r.Context(), confine.EventWorkloadRevoked, gwaudit.GatewayEvent{
			AgentID:    res.WorkloadID,
			Action:     "workload.revoke",
			Decision:   "deny",
			ReasonCode: req.Reason,
			ResourceID: strings.TrimSpace(fmt.Sprintf("connections_closed=%d %s", res.ConnectionsClosed, killed)),
			LatencyMS:  res.Latency.Milliseconds(),
			StartedAt:  res.At,
			FinishedAt: time.Now().UTC(),
		}); err != nil {
			logger.Error("could not record revocation", slog.Any("error", err))
		}

		logger.Warn("workload revoked",
			slog.String("workload", res.WorkloadID),
			slog.String("reason", req.Reason),
			slog.Int("connections_closed", res.ConnectionsClosed),
			slog.Duration("latency", res.Latency))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"workload":           res.WorkloadID,
			"connections_closed": res.ConnectionsClosed,
			"workload_process":   killed,
			"latency_us":         res.Latency.Microseconds(),
			"reason":             req.Reason,
		})
	})

	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		allowed, denied := proxy.Stats()
		seq, head := sink.Head()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"allowed":        allowed,
			"denied":         denied,
			"chain_seq":      seq,
			"chain_head":     head,
			"signed_through": sink.SignedThrough(),
			"checkpoint_error": func() string {
				if err := sink.CheckpointError(); err != nil {
					return err.Error()
				}
				return ""
			}(),
		})
	})

	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()

	return srv, ln, nil
}

func dirOf(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return "."
}
