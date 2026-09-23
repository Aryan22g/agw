//go:build !linux

package netns

import (
	"context"
	"time"
)

// Refusals is unavailable off Linux.
func (s *Sandbox) Refusals() (RefusalCounts, error) { return RefusalCounts{}, ErrUnsupported }

// WatchRefusals is unavailable off Linux.
func (s *Sandbox) WatchRefusals(context.Context, time.Duration, RefusalHandler) error {
	return ErrUnsupported
}
