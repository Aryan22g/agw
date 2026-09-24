package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Aryan22g/agw/internal/confine"
	"github.com/Aryan22g/agw/internal/recorder"
	gwaudit "github.com/Aryan22g/agw/pkg/evidence"

	"google.golang.org/grpc"
)

// runWatch is Level 0 of the adoption ladder: accept the telemetry an agent
// already emits, and turn it into a signed, hash-linked record anyone can
// verify.
//
// Nothing is enforced here, and the output says so on every line. It records
// what the agent REPORTS, which a compromised agent can lie about. That is the
// honest boundary between this and `agw run`, and blurring it would make the
// stronger claim unbelievable too.
// tokenHint renders the token for the banner, or says plainly that there is
// none.
func tokenHint(token string, insecure bool) string {
	if insecure {
		return "<none -- running with --insecure; anything that reaches this port can append records>"
	}
	return token
}

func runWatch(args []string) error {
	fs := flagSet("watch")
	var (
		listen       = fs.String("listen", "127.0.0.1:4318", "OTLP/HTTP listen address (JSON or protobuf)")
		grpcListen   = fs.String("grpc-listen", "127.0.0.1:4317", "OTLP/gRPC listen address (\"off\" to disable)")
		evidencePath = fs.String("out", "", "evidence chain output (default: agw-evidence-<ts>.jsonl)")
		keyPath      = fs.String("key", "", "checkpoint key: a file, unix:SOCKET for ags-signd, or none (default: ~/.agw/checkpoint.key)")
		policyPath   = fs.String("policy", "", "egress policy to evaluate against, in report-only mode")
		token        = fs.String("token", "", "bearer token exporters must present (generated if empty)")
		insecure     = fs.Bool("insecure", false, "accept exports with no token at all")
		checkpointN  = fs.Uint64("checkpoint-every", 100, "write a signed checkpoint every N records")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *evidencePath == "" {
		*evidencePath = fmt.Sprintf("agw-evidence-%s.jsonl", time.Now().UTC().Format("20060102-150405"))
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ck, err := resolveCheckpointKey(*keyPath)
	if err != nil {
		return err
	}
	defer ck.Close()

	sinkCfg := gwaudit.EvidenceSinkConfig{Path: *evidencePath, CheckpointEvery: *checkpointN, CheckpointInterval: agwCheckpointInterval}
	ck.apply(&sinkCfg)

	sink, err := gwaudit.NewEvidenceSink(sinkCfg)
	if err != nil {
		return err
	}
	defer sink.Close()

	// A token is generated rather than defaulted to none, so the secure path
	// is the one that costs nothing. --insecure remains for an operator who
	// has decided the exposure is acceptable and says so.
	if *token == "" && !*insecure {
		var b [24]byte
		if _, err := rand.Read(b[:]); err != nil {
			return fmt.Errorf("generate token: %w", err)
		}
		*token = base64.RawURLEncoding.EncodeToString(b[:])
	}

	recCfg := recorder.Config{
		Sink:                 sink,
		Logger:               logger,
		Token:                *token,
		AllowUnauthenticated: *insecure,
	}

	var evaluator *recorder.Evaluator
	if *policyPath != "" {
		policy, err := confine.LoadPolicy(*policyPath)
		if err != nil {
			return err
		}
		ev, err := recorder.NewEvaluator(policy)
		if err != nil {
			return err
		}
		recCfg.Evaluator = ev
		evaluator = ev
	}

	rec, err := recorder.New(recCfg)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              *listen,
		Handler:           rec.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}

	mode := "recording"
	if *policyPath != "" {
		mode = "recording, and evaluating policy in report-only mode"
	}

	// Bind before printing the banner, so the instructions are only shown
	// for a receiver that is actually listening.
	httpLn, err := net.Listen("tcp", *listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", *listen, err)
	}

	var grpcSrv *grpc.Server
	var grpcLn net.Listener
	if *grpcListen != "" && *grpcListen != "off" {
		grpcLn, err = net.Listen("tcp", *grpcListen)
		if err != nil {
			return fmt.Errorf("listen on %s for OTLP/gRPC (pass --grpc-listen off to skip it): %w",
				*grpcListen, err)
		}
		grpcSrv = grpc.NewServer(grpc.MaxRecvMsgSize(8 << 20))
		rec.GRPCService().Register(grpcSrv)
	}

	fmt.Fprintf(os.Stderr, "agw: %s to %s\n", mode, *evidencePath)
	fmt.Fprintf(os.Stderr, "agw: checkpoints signed by %s\n\n", ck.Source)
	fmt.Fprintf(os.Stderr, "  Point any OpenTelemetry exporter at this process -- defaults are fine:\n\n")
	fmt.Fprintf(os.Stderr, "    export OTEL_EXPORTER_OTLP_ENDPOINT=http://%s\n", *listen)
	fmt.Fprintf(os.Stderr, "    export OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf   # or http/json\n")
	if !*insecure {
		fmt.Fprintf(os.Stderr, "    export OTEL_EXPORTER_OTLP_HEADERS=\"Authorization=Bearer %s\"\n", *token)
	}
	if grpcLn != nil {
		fmt.Fprintf(os.Stderr, "\n  gRPC exporters: OTEL_EXPORTER_OTLP_ENDPOINT=http://%s with protocol grpc\n", *grpcListen)
	}
	if *insecure {
		fmt.Fprintf(os.Stderr, "\n  %s\n", tokenHint(*token, *insecure))
	}
	fmt.Fprintf(os.Stderr, `
  Nothing is enforced. This records what the agent reports, which a
  compromised agent can lie about. Use 'agw run' for containment.

`)

	errCh := make(chan error, 2)
	go func() {
		if err := srv.Serve(httpLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	if grpcSrv != nil {
		go func() {
			if err := grpcSrv.Serve(grpcLn); err != nil {
				errCh <- err
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		return err
	case <-stop:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	if grpcSrv != nil {
		grpcSrv.GracefulStop()
	}

	if err := sink.Checkpoint(); err != nil {
		fmt.Fprintf(os.Stderr, "agw: final checkpoint: %v\n", err)
	}

	spans, recorded, rejected := rec.Stats()
	seq, _ := sink.Head()
	fmt.Fprintf(os.Stderr, "\nagw: %d spans seen, %d recorded, %d exports rejected\n",
		spans, recorded, rejected)

	if *policyPath != "" {
		shadow := rec.Shadow()
		fmt.Fprintf(os.Stderr, "agw: %s\n", shadow.Summary())
		if shadow.WouldDeny > 0 {
			fmt.Fprintf(os.Stderr, "agw: see them with  agw audit show %s --would-deny\n",
				*evidencePath)
		}
		if unknown := evaluator.UnknownAgents(); len(unknown) > 0 {
			fmt.Fprintf(os.Stderr,
				"agw: the policy names no workload for %s, so everything they did would be refused.\n"+
					"agw: a workload id must match the agent's name: its OpenTelemetry service.name\n"+
					"agw: (OTEL_SERVICE_NAME) or gen_ai.agent.name. Rename one or the other.\n",
				strings.Join(unknown, ", "))
		}
		if shadow.NotEvaluable > 0 {
			fmt.Fprintf(os.Stderr,
				"agw: %d observations were outside this policy's reach; enforcing it would not "+
					"have covered them\n", shadow.NotEvaluable)
		}
	}
	fmt.Fprintf(os.Stderr, "agw: evidence %s (%d records)\n", *evidencePath, seq)
	fmt.Fprintf(os.Stderr, "agw: verify with  %s\n", ck.verifyHint(*evidencePath))
	return nil
}
