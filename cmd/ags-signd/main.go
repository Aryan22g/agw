// Command ags-signd holds a private key and signs on request.
//
// It exists so the gateway does not have to hold its own signing key. The
// gateway terminates untrusted network traffic; this process does not listen
// on the network at all. A compromise of the gateway can ask this daemon for
// signatures for as long as it holds the process, but cannot take the key
// with it -- so evicting the attacker actually ends their capability, which is
// not true when the key is a file the gateway can read.
//
// This is deliberately the same shape a KMS or PKCS#11 HSM takes, so moving to
// one later is a change of backend rather than a change of design.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Aryan22g/agw/pkg/ags1/signer"
)

func main() {
	var (
		socket   = flag.String("socket", "/run/agentgateway/sign.sock", "unix socket to listen on")
		keyPath  = flag.String("key", "", "path to the base64 Ed25519 private key")
		keyID    = flag.String("key-id", "", "key id to advertise (default: the AGS1 thumbprint)")
		purposes = flag.String("purposes", "",
			"comma-separated purposes this daemon signs for: principal-context, evidence-checkpoint, "+
				"readiness-probe (default: all). Run one daemon per key, each with only its purpose, "+
				"so a daemon holding the checkpoint key cannot mint principal assertions.")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *keyPath == "" {
		fmt.Fprintln(os.Stderr, "ags-signd: -key is required")
		os.Exit(2)
	}

	held, err := signer.FromFile(*keyPath, *keyID)
	if err != nil {
		logger.Error("load key", slog.Any("error", err))
		os.Exit(1)
	}

	var allowed []string
	for _, p := range strings.Split(*purposes, ",") {
		if p = strings.TrimSpace(p); p != "" {
			allowed = append(allowed, p)
		}
	}

	daemon, err := signer.NewDaemon(signer.DaemonConfig{
		SocketPath: *socket,
		Signer:     held,
		Logger:     logger,
		Purposes:   allowed,
	})
	if err != nil {
		logger.Error("start daemon", slog.Any("error", err))
		os.Exit(1)
	}

	logger.Info("signing daemon listening",
		slog.String("socket", *socket),
		slog.String("key_id", held.KeyID()),
		slog.Any("purposes", allowedOrAll(allowed)),
		slog.String("note", "the key is held here and is never returned to callers"),
	)

	go func() {
		if err := daemon.Serve(); err != nil {
			logger.Error("serve", slog.Any("error", err))
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("shutting down", slog.Uint64("signatures_produced", daemon.Stats()))
	_ = daemon.Close()
}

func allowedOrAll(p []string) []string {
	if len(p) == 0 {
		return []string{"principal-context", "evidence-checkpoint", "readiness-probe"}
	}
	return p
}
