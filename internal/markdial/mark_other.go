//go:build !linux

package markdial

import "syscall"

// control is a no-op on non-Linux platforms (dev builds).
func control(mark uint32) func(network, address string, c syscall.RawConn) error {
	return nil
}
