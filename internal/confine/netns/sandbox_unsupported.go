//go:build !linux

package netns

import "context"
import "os/exec"

// Create is unavailable off Linux. It returns an error rather than silently
// doing nothing: a confinement boundary that quietly fails to exist is worse
// than one that refuses to start.
func Create(Config) (*Sandbox, error) { return nil, ErrUnsupported }

// Command is unavailable off Linux.
func (s *Sandbox) Command(context.Context, ...string) (*exec.Cmd, error) {
	return nil, ErrUnsupported
}

// Destroy is a no-op off Linux.
func (s *Sandbox) Destroy() error { return ErrUnsupported }

// Available reports whether this platform can build a sandbox.
func Available() bool { return false }
