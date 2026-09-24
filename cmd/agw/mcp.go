package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Aryan22g/agw/internal/mcp"
	"github.com/Aryan22g/agw/pkg/authz"
	gwaudit "github.com/Aryan22g/agw/pkg/evidence"
	"github.com/Aryan22g/agw/pkg/routing"
)

// runMCP is Level 2: tool calls are actually refused, at the layer where an
// agent does the things that matter.
//
// Two transports, one enforcer:
//
//	agw mcp --policy P --agent A --upstream http://host/mcp       (HTTP server)
//	agw mcp --policy P --agent A -- npx -y some-mcp-server ...     (stdio server)
//
// The stdio form is the one most people need: desktop clients, IDEs and
// coding agents launch MCP servers as subprocesses, so putting agw in front of
// one is a change to the command in the client's config and nothing else.
//
// Still cooperative -- the agent routes through here because it was
// configured to, and a compromised one can decline. `agw run` is where that
// stops being a choice.
func runMCP(args []string) error {
	var command []string
	for i, a := range args {
		if a == "--" {
			command = args[i+1:]
			args = args[:i]
			break
		}
	}

	fs := flagSet("mcp")
	var (
		upstream     = fs.String("upstream", "", "HTTP MCP server to front (or give a stdio server command after --)")
		listen       = fs.String("listen", "127.0.0.1:8900", "HTTP mode: address to accept MCP traffic on")
		policyDir    = fs.String("policy-dir", "", "directory of tenant policy files")
		policyFile   = fs.String("policy", "", "a single action policy file (alternative to --policy-dir)")
		tenant       = fs.String("tenant", "", "tenant id (default: the tenant named in --policy)")
		agent        = fs.String("agent", "", "agent id every tool call is attributed to")
		evidencePath = fs.String("evidence", "", "evidence chain output (default: under $AGW_HOME/evidence in stdio mode)")
		keyPath      = fs.String("key", "", "checkpoint key: a file, unix:SOCKET for ags-signd, or none (default: ~/.agw/checkpoint.key)")
		pinTools     = fs.Bool("pin-tools", false,
			"refuse every tool call once the server changes the tools it advertises (the rug pull)")
		defaultRisk = fs.String("default-risk", "destructive",
			"risk class for tools with no override: read, write, privileged, destructive")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	stdio := len(command) > 0
	switch {
	case stdio && *upstream != "":
		return errors.New("give either --upstream URL or a server command after --, not both")
	case !stdio && *upstream == "":
		return errors.New("give --upstream URL for an HTTP server, or a stdio server command after --")
	}
	if (*policyDir == "") == (*policyFile == "") {
		return errors.New("give exactly one of --policy FILE or --policy-dir DIR")
	}
	if *agent == "" {
		return errors.New("--agent is required: it is the identity every tool call is attributed to")
	}

	// In stdio mode stdout IS the protocol. Every human-readable line goes
	// to stderr, which MCP clients show in their server log.
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	var policies map[string]*authz.Policy
	if *policyFile != "" {
		p, err := authz.LoadPolicyFile(*policyFile)
		if err != nil {
			return err
		}
		policies = map[string]*authz.Policy{p.Tenant: p}
		if *tenant == "" {
			*tenant = p.Tenant
		}
	} else {
		var err error
		if policies, err = authz.LoadPolicyDir(*policyDir); err != nil {
			return err
		}
		if *tenant == "" {
			return errors.New("--tenant is required with --policy-dir")
		}
	}
	if _, ok := policies[*tenant]; !ok {
		// A tenant with no policy is denied everything, which is correct but
		// looks like a broken deployment.
		return fmt.Errorf("no policy for tenant %q; every tool call would be denied", *tenant)
	}
	engine, err := authz.NewNativeEngine(policies)
	if err != nil {
		return err
	}

	risk := routing.RiskClass(*defaultRisk)
	switch risk {
	case routing.RiskRead, routing.RiskWrite, routing.RiskPrivileged, routing.RiskDestructive:
	default:
		return fmt.Errorf("--default-risk %q is not a risk class", *defaultRisk)
	}

	if *evidencePath == "" {
		stamp := time.Now().UTC().Format("20060102-150405")
		if stdio {
			// A desktop client starts this with a working directory nobody
			// chose, so the evidence goes somewhere findable instead.
			home, err := agwHome()
			if err != nil {
				return err
			}
			dir := filepath.Join(home, "evidence")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			*evidencePath = filepath.Join(dir, fmt.Sprintf("mcp-%s-%s.jsonl", safeName(*agent), stamp))
		} else {
			*evidencePath = fmt.Sprintf("agw-mcp-%s.jsonl", stamp)
		}
	}

	ck, err := resolveCheckpointKey(*keyPath)
	if err != nil {
		return err
	}
	defer ck.Close()
	sinkCfg := gwaudit.EvidenceSinkConfig{Path: *evidencePath, CheckpointEvery: 50, CheckpointInterval: mcpCheckpointInterval}
	ck.apply(&sinkCfg)
	sink, err := gwaudit.NewEvidenceSink(sinkCfg)
	if err != nil {
		return err
	}
	defer sink.Close()

	cfg := mcp.Config{
		Authorizer: engine, Sink: sink, Logger: logger,
		TenantID: *tenant, AgentID: *agent, DefaultRiskClass: risk, PinTools: *pinTools,
	}

	var stats func() (uint64, uint64, uint64)
	if stdio {
		stats, err = serveMCPStdio(cfg, command, logger, func() {
			if cerr := sink.Checkpoint(); cerr != nil {
				fmt.Fprintf(os.Stderr, "agw: checkpoint at end of session: %v\n", cerr)
			}
		})
	} else {
		stats, err = serveMCPHTTP(cfg, *upstream, *listen, risk)
	}

	if cerr := sink.Checkpoint(); cerr != nil {
		fmt.Fprintf(os.Stderr, "agw: final checkpoint: %v\n", cerr)
	}
	if stats != nil {
		allowed, denied, changes := stats()
		fmt.Fprintf(os.Stderr, "agw: %d tool calls allowed, %d refused\n", allowed, denied)
		if changes > 0 {
			fmt.Fprintf(os.Stderr,
				"agw: the server changed its advertised tools %d time(s) -- review before trusting it\n", changes)
		}
	}
	fmt.Fprintf(os.Stderr, "agw: evidence %s\n", *evidencePath)
	fmt.Fprintf(os.Stderr, "agw: verify with  %s\n", ck.verifyHint(*evidencePath))
	return err
}

func serveMCPHTTP(cfg mcp.Config, upstream, listen string, risk routing.RiskClass) (func() (uint64, uint64, uint64), error) {
	up, err := url.Parse(upstream)
	if err != nil || up.Host == "" {
		return nil, fmt.Errorf("--upstream %q is not a URL", upstream)
	}
	cfg.Upstream = up
	proxy, err := mcp.New(cfg)
	if err != nil {
		return nil, err
	}

	srv := &http.Server{Addr: listen, Handler: proxy, ReadHeaderTimeout: 15 * time.Second}
	fmt.Fprintf(os.Stderr, `agw: MCP enforcement point on %s -> %s
  tenant %s, agent %s, default risk %s, pin tools %v

  Point the agent's MCP client at http://%s instead of the server directly.
  Tool calls are refused as JSON-RPC errors, not HTTP errors.

`, listen, up, cfg.TenantID, cfg.AgentID, risk, cfg.PinTools, listen)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		return proxy.Stats, err
	case <-stop:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	return proxy.Stats, nil
}

// serveMCPStdio launches the server as a subprocess and sits on its pipes.
// mcpCheckpointInterval is how long a record can sit unsigned in an MCP
// session. Clients end stdio servers abruptly -- Claude Code sends SIGTERM and
// then SIGKILL soon after -- so a session's records must be signed while it is
// still running, not only at a clean exit. One signature per second, and only
// when there is something new.
const mcpCheckpointInterval = time.Second

// serveMCPStdio runs the stdio enforcement point. sessionEnded is called as
// soon as the client's session is over, before the server is reaped: the
// client may kill this process at any moment after closing its side.
func serveMCPStdio(cfg mcp.Config, command []string, logger *slog.Logger, sessionEnded func()) (func() (uint64, uint64, uint64), error) {
	backend := "stdio:" + strings.Join(command, " ")
	enf, err := mcp.NewEnforcer(cfg, backend)
	if err != nil {
		return nil, err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cmd := exec.Command(command[0], command[1:]...)
	cmd.Stderr = os.Stderr // the server's own log, shown by the client
	serverIn, err := cmd.StdinPipe()
	if err != nil {
		return enf.Stats, err
	}
	serverOut, err := cmd.StdoutPipe()
	if err != nil {
		return enf.Stats, err
	}
	if err := cmd.Start(); err != nil {
		return enf.Stats, fmt.Errorf("start MCP server %q: %w", command[0], err)
	}
	logger.Info("MCP enforcement point on stdio",
		slog.String("server", backend), slog.String("tenant", cfg.TenantID),
		slog.String("agent", cfg.AgentID), slog.Bool("pin_tools", cfg.PinTools))

	serveErr := enf.ServeStdio(ctx, os.Stdin, os.Stdout, serverIn, serverOut)
	if errors.Is(serveErr, context.Canceled) {
		serveErr = nil // stopped by a signal: a normal end of session
	}
	sessionEnded()

	// Give the server a moment to exit on its own after its input closed,
	// then stop it: an orphaned MCP server keeps whatever it holds open.
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case <-exited:
	case <-time.After(3 * time.Second):
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-exited:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
	}
	return enf.Stats, serveErr
}

// safeName makes an agent id usable in a file name.
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		}
		return '_'
	}, s)
}
