//go:build !linux

package nftsetup

import "fmt"

// Apply is a no-op error on non-Linux (dev builds). nftables is Linux-only.
func Apply(cfg *Config) error {
	return fmt.Errorf("nftsetup: nftables is Linux-only; skipping on this platform")
}

// Unapply is a no-op on non-Linux.
func Unapply(cfg *Config) error { return nil }
