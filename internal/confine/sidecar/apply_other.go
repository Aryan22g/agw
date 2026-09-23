//go:build !linux

package sidecar

import "errors"

// Apply is Linux-only: the rules are nftables in a network namespace.
func Apply(Config) error { return errors.New("sidecar: needs Linux (nftables)") }

// Refused is Linux-only.
func Refused() (uint64, error) { return 0, errors.New("sidecar: needs Linux (nftables)") }
