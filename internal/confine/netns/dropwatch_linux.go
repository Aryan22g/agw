//go:build linux

package netns

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// Counter names inside our own table. Scoped to the table, so plain names are
// unambiguous.
const (
	counterMetadata = "refused_metadata"
	counterPrivate  = "refused_private"
	counterOther    = "refused_other"
	counterHostPort = "refused_hostport"
)

// Refusals reads the firewall's counters.
//
// Exact and lossless: the kernel increments these per packet with no shared
// buffer to overflow and no rate limit to drop entries.
func (s *Sandbox) Refusals() (RefusalCounts, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "nft", "-j", "list", "counters", "table", "inet", s.table).Output()
	if err != nil {
		return RefusalCounts{}, fmt.Errorf("netns: read counters: %w", err)
	}

	var doc struct {
		Nftables []struct {
			Counter *struct {
				Name    string `json:"name"`
				Packets uint64 `json:"packets"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return RefusalCounts{}, fmt.Errorf("netns: parse counters: %w", err)
	}

	var c RefusalCounts
	for _, entry := range doc.Nftables {
		if entry.Counter == nil {
			continue
		}
		switch entry.Counter.Name {
		case counterMetadata:
			c.Metadata = entry.Counter.Packets
		case counterPrivate:
			c.Private = entry.Counter.Packets
		case counterOther:
			c.Other = entry.Counter.Packets
		case counterHostPort:
			c.HostPort = entry.Counter.Packets
		}
	}
	return c, nil
}

// WatchRefusals polls the counters and reports increases.
//
// Polling rather than streaming is a deliberate trade. It cannot attribute a
// refusal to a precise moment -- only to the interval it was observed in --
// and that is fine for the question being asked. What it buys is a mechanism
// with no dependency on a readable kernel log, which is what makes this work
// inside a container.
func (s *Sandbox) WatchRefusals(ctx context.Context, interval time.Duration, handle RefusalHandler) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}

	previous, err := s.Refusals()
	if err != nil {
		return err
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	emit := func() error {
		current, err := s.Refusals()
		if err != nil {
			return err
		}
		prev := previous.ByCategory()
		for category, total := range current.ByCategory() {
			if delta := total - prev[category]; delta > 0 {
				handle(Refusal{
					Sandbox:  s.name,
					Category: category,
					Delta:    delta,
					Total:    total,
					At:       time.Now().UTC(),
				})
			}
		}
		previous = current
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			// A final read, so refusals in the last interval are not lost
			// when the workload exits immediately after making them.
			_ = emit()
			return nil
		case <-ticker.C:
			if err := emit(); err != nil {
				return err
			}
		}
	}
}
