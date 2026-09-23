package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/Aryan22g/agw/internal/confine"
	"github.com/Aryan22g/agw/internal/confine/netns"
	gwaudit "github.com/Aryan22g/agw/internal/gateway/audit"
)

// runRun is the single-command path: build a sandbox, run a workload inside
// it, and leave behind an evidence file that verifies on its own.
//
//	agw run --policy eval.yaml -- python harness.py
//
// The point is that a researcher gets containment and a reproducibility
// artifact from one command, with no infrastructure to stand up and nothing
// leaving the machine.
func runRun(args []string) error {
	fs := flagSet("run")
	var (
		policyPath   = fs.String("policy", "", "egress policy file")
		evidencePath = fs.String("evidence", "", "evidence chain output (default: agw-evidence-<ts>.jsonl)")
		keyPath      = fs.String("key", "", "checkpoint key: a file, unix:SOCKET for ags-signd, or none (default: ~/.agw/checkpoint.key)")
		workloadID   = fs.String("workload", "", "workload id from the policy (default: the only one)")
		subnet       = fs.String("subnet", "10.77.0.0/30", "point-to-point link for the sandbox")
		proxyPort    = fs.Int("proxy-port", 18080, "port the sandbox may reach on the host")
		quiet        = fs.Bool("quiet", false, "suppress the summary")
		adminSocket  = fs.String("admin", "/var/run/agw/admin.sock",
			"unix socket for `agw suspend` / `agw status`; never a network port")
		inheritEnv = fs.Bool("inherit-env", false,
			"pass this shell's ENTIRE environment to the workload, secrets included (not recommended)")
		envFlags workloadFlags
	)
	fs.Var(&envFlags, "env", "pass NAME from this environment, or set NAME=VALUE, in the workload (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	argv := fs.Args()
	if len(argv) == 0 {
		return errors.New("no command given; usage: agw run --policy FILE -- COMMAND [ARGS...]")
	}
	if *policyPath == "" {
		return errors.New("--policy is required")
	}
	if !netns.Available() {
		return fmt.Errorf("%w (agw run needs the ip and nft binaries and root)", netns.ErrUnsupported)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	policy, err := confine.LoadPolicy(*policyPath)
	if err != nil {
		return err
	}

	id := *workloadID
	if id == "" {
		ids := policy.WorkloadIDs()
		if len(ids) != 1 {
			return fmt.Errorf("--workload is required: the policy names %d workloads", len(ids))
		}
		id = ids[0]
	}

	if *evidencePath == "" {
		*evidencePath = fmt.Sprintf("agw-evidence-%s.jsonl", time.Now().UTC().Format("20060102-150405"))
	}

	link, err := netip.ParsePrefix(*subnet)
	if err != nil {
		return fmt.Errorf("--subnet: %w", err)
	}

	// --- containment -----------------------------------------------------
	sandbox, err := netns.Create(netns.Config{
		Name:      "run",
		Subnet:    link,
		ProxyPort: *proxyPort,
	})
	if err != nil {
		return err
	}
	defer func() {
		if err := sandbox.Destroy(); err != nil {
			fmt.Fprintf(os.Stderr, "agw: sandbox teardown: %v\n", err)
		}
	}()

	// --- evidence --------------------------------------------------------
	sinkCfg := gwaudit.EvidenceSinkConfig{Path: *evidencePath, CheckpointEvery: 50, CheckpointInterval: agwCheckpointInterval}
	ck, err := resolveCheckpointKey(*keyPath)
	if err != nil {
		return err
	}
	defer ck.Close()
	ck.apply(&sinkCfg)
	sink, err := gwaudit.NewEvidenceSink(sinkCfg)
	if err != nil {
		return err
	}
	defer sink.Close()

	// --- enforcement -----------------------------------------------------
	guard, err := confine.NewGuard(policy.PermitPrivate)
	if err != nil {
		return err
	}
	resolver, err := confine.NewResolver(confine.ResolverConfig{Guard: guard})
	if err != nil {
		return err
	}

	registry := confine.NewRegistry()
	if err := registry.Register(confine.Identity{
		WorkloadID: id,
		TenantID:   "local",
		SourceAddr: sandbox.GuestIP(),
		Command:    fmt.Sprintf("%v", argv),
		AttestedAt: time.Now().UTC(),
	}); err != nil {
		return err
	}

	proxy, err := confine.NewProxy(confine.ProxyConfig{
		Policy:   policy,
		Registry: registry,
		Resolver: resolver,
		Sink:     sink,
		Logger:   logger,
	})
	if err != nil {
		return err
	}

	// Bound to the host side of the point-to-point link, not a wildcard: the
	// proxy is reachable from this sandbox and from nothing else on the host.
	ln, err := net.Listen("tcp", sandbox.ProxyAddr())
	if err != nil {
		return fmt.Errorf("listen on %s: %w", sandbox.ProxyAddr(), err)
	}
	srv := &http.Server{Handler: proxy, ReadHeaderTimeout: 15 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	if !*quiet {
		fmt.Fprintf(os.Stderr, "agw: sandbox %s  workload %s at %s  proxy %s\n",
			sandbox.Name(), id, sandbox.GuestIP(), sandbox.ProxyAddr())
	}

	// Packets the firewall refuses never reach the proxy, so without this the
	// evidence would describe what the workload asked the proxy for rather
	// than what it attempted. A direct probe of the metadata endpoint is the
	// higher-signal event and it only appears here.
	watchCtx, stopWatch := context.WithCancel(context.Background())
	defer stopWatch()

	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		err := sandbox.WatchRefusals(watchCtx, 2*time.Second, func(r netns.Refusal) {
			if _, err := sink.Write(context.Background(), confine.EventEgressRefusedAtFirewall,
				gwaudit.GatewayEvent{
					TenantID:     "local",
					AgentID:      id,
					Action:       "net.connect",
					ResourceType: "category",
					ResourceID:   r.Category,
					Decision:     "deny",
					ReasonCode:   r.Category,
					BackendID:    fmt.Sprintf("packets=%d total=%d", r.Delta, r.Total),
					SourceIP:     sandbox.GuestIP().String(),
					Producer:     gwaudit.ProducerConfineFirewall,
					StartedAt:    r.At,
					FinishedAt:   r.At,
				}); err != nil {
				fmt.Fprintf(os.Stderr, "agw: could not record firewall refusal: %v\n", err)
			}
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "agw: refusal watcher stopped: %v\n", err)
		}
	}()

	// --- the workload ----------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	env, err := workloadEnv(os.Environ(), envFlags, *inheritEnv)
	if err != nil {
		return err
	}
	sandbox.SetEnv(env)
	cmd, err := sandbox.Command(ctx, argv...)
	if err != nil {
		return err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	ownProcessGroup(cmd)

	// The kill switch. `agw suspend --workload ID` from another terminal
	// cuts every connection at the proxy, refuses new ones, and then kills
	// the workload's whole process group -- three levels, none of which asks
	// the workload.
	var suspended atomic.Bool
	adminSrv, adminLn, err := startAdmin(*adminSocket, proxy, registry, sink, logger, func(string) string {
		suspended.Store(true)
		if err := killGroup(cmd); err != nil {
			return "workload_kill_failed=" + err.Error()
		}
		return "workload_killed=true"
	})
	if err != nil {
		return err
	}
	defer func() {
		_ = adminSrv.Close()
		_ = adminLn.Close()
		_ = os.Remove(*adminSocket)
	}()
	if !*quiet {
		fmt.Fprintf(os.Stderr, "agw: kill switch  agw suspend --workload %s --admin %s\n", id, *adminSocket)
	}

	runErr := cmd.Run()
	if suspended.Load() && !*quiet {
		fmt.Fprintf(os.Stderr, "agw: workload %s was suspended by the kill switch\n", id)
	}

	// Stop the watcher and let its final read land before checkpointing, so
	// refusals in the last interval are in the chain rather than lost.
	stopWatch()
	select {
	case <-watchDone:
	case <-time.After(5 * time.Second):
	}

	// A final checkpoint pins the chain through the last record, rather than
	// leaving it at whatever the last periodic checkpoint covered.
	if err := sink.Checkpoint(); err != nil {
		fmt.Fprintf(os.Stderr, "agw: final checkpoint: %v\n", err)
	}

	if !*quiet {
		allowed, denied := proxy.Stats()
		seq, _ := sink.Head()
		fmt.Fprintf(os.Stderr, "\nagw: egress allowed %d, denied %d (at the proxy)\n", allowed, denied)

		if counts, err := sandbox.Refusals(); err == nil && counts.Total() > 0 {
			fmt.Fprintf(os.Stderr,
				"agw: refused at the firewall: metadata %d, private %d, external %d, host %d\n",
				counts.Metadata, counts.Private, counts.Other, counts.HostPort)
		}
		fmt.Fprintf(os.Stderr, "agw: evidence %s (%d records)\n", *evidencePath, seq)
		fmt.Fprintf(os.Stderr, "agw: verify with  %s\n", ck.verifyHint(*evidencePath))
	}

	var exit *exec.ExitError
	if errors.As(runErr, &exit) {
		// The workload's exit status is the command's own result, not ours.
		os.Exit(exit.ExitCode())
	}
	return runErr
}

// workloadEnv decides what environment crosses into the sandbox.
//
// By default almost nothing does: PATH, HOME, locale and terminal settings.
// The operator's shell holds cloud credentials, API tokens and the path to
// the checkpoint key, and an agent that can read its own environment can
// read all of them -- step 4a of the July 2026 Hugging Face intrusion was
// exactly that. What the workload legitimately needs, such as its model API
// key, is named with --env, so it is a decision somebody made and can see.
func workloadEnv(host []string, flags []string, inherit bool) ([]string, error) {
	if inherit {
		fmt.Fprintln(os.Stderr, "agw: --inherit-env: the workload receives this shell's entire environment, "+
			"including any credentials in it")
		return append([]string(nil), host...), nil
	}
	env := netns.MinimalEnv(host)
	lookup := make(map[string]string, len(host))
	for _, kv := range host {
		if k, v, ok := strings.Cut(kv, "="); ok {
			lookup[k] = v
		}
	}
	for _, f := range flags {
		if k, _, ok := strings.Cut(f, "="); ok {
			if k == "" {
				return nil, fmt.Errorf("--env %q: empty name", f)
			}
			env = append(env, f)
			continue
		}
		v, ok := lookup[f]
		if !ok {
			return nil, fmt.Errorf("--env %s: not set in this environment (use --env %s=VALUE to set it)", f, f)
		}
		env = append(env, f+"="+v)
	}
	return env, nil
}
