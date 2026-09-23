package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// adminClient talks to a running proxy over its unix socket. There is no
// network transport on purpose: the control interface that can revoke a
// workload must not be reachable from the network that workload is on.
func adminClient(socket string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}
}

func runRevoke(args []string) error {
	fs := flagSet("revoke")
	var (
		socket   = fs.String("admin", "/var/run/agw/admin.sock", "proxy control socket")
		workload = fs.String("workload", "", "workload id to revoke")
		reason   = fs.String("reason", "revoked by operator", "reason recorded in the evidence chain")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workload == "" {
		return errors.New("--workload is required")
	}

	body, _ := json.Marshal(map[string]string{"workload": *workload, "reason": *reason})

	start := time.Now()
	resp, err := adminClient(*socket).Post(
		"http://agw/revoke", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("contact proxy on %s: %w", *socket, err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy refused: %s", bytes.TrimSpace(raw))
	}

	var out struct {
		Workload          string `json:"workload"`
		ConnectionsClosed int    `json:"connections_closed"`
		LatencyUS         int64  `json:"latency_us"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("%s revoked\n", out.Workload)
	fmt.Printf("  connections closed  %d\n", out.ConnectionsClosed)
	fmt.Printf("  teardown            %s\n", time.Duration(out.LatencyUS)*time.Microsecond)
	fmt.Printf("  round trip          %s\n", time.Since(start).Round(time.Microsecond))
	return nil
}

func runStatus(args []string) error {
	fs := flagSet("status")
	socket := fs.String("admin", "/var/run/agw/admin.sock", "proxy control socket")
	if err := fs.Parse(args); err != nil {
		return err
	}

	resp, err := adminClient(*socket).Get("http://agw/status")
	if err != nil {
		return fmt.Errorf("contact proxy on %s: %w", *socket, err)
	}
	defer resp.Body.Close()

	var out struct {
		Allowed   uint64 `json:"allowed"`
		Denied    uint64 `json:"denied"`
		ChainSeq  uint64 `json:"chain_seq"`
		ChainHead string `json:"chain_head"`
		Signed    uint64 `json:"signed_through"`
		CPError   string `json:"checkpoint_error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return fmt.Errorf("parse response: %w", err)
	}

	fmt.Printf("allowed      %d\n", out.Allowed)
	fmt.Printf("denied       %d\n", out.Denied)
	fmt.Printf("chain seq    %d\n", out.ChainSeq)
	fmt.Printf("signed thru  %d", out.Signed)
	if out.ChainSeq > out.Signed {
		fmt.Printf("  (%d record(s) not yet under a checkpoint)", out.ChainSeq-out.Signed)
	}
	fmt.Println()
	if out.CPError != "" {
		fmt.Printf("CHECKPOINTS FAILING  %s\n", out.CPError)
		fmt.Printf("                     records are still written and chained, but not signed\n")
	}
	if len(out.ChainHead) > 16 {
		fmt.Printf("chain head   %s...\n", out.ChainHead[:16])
	}
	return nil
}
