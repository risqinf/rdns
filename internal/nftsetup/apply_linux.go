//go:build linux

package nftsetup

import (
	"bytes"
	"fmt"
	"os/exec"
)

// Apply writes the rendered nft script to `nft -f` (additive: flush+recreate
// only this project's table). It is idempotent.
func Apply(cfg *Config) error {
	if _, err := exec.LookPath("nft"); err != nil {
		return fmt.Errorf("nftsetup: nft not found: %w", err)
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(cfg.Render())
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nftsetup: nft: %v\n%s", err, out.String())
	}
	return nil
}

// Unapply removes the table.
func Unapply(cfg *Config) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(cfg.UninstallScript())
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nftsetup: nft: %v\n%s", err, out.String())
	}
	return nil
}
