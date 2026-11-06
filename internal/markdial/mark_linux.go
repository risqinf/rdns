//go:build linux

package markdial

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// control returns a net.Dialer.Control function that stamps the socket with
// SO_MARK before connect(2) or bind(2) is called. This guarantees the initial
// TCP SYN packet carries the mark and is not redirected back into nftables.
func control(mark uint32) func(network, address string, c syscall.RawConn) error {
	if mark == 0 {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		var operr error
		if err := c.Control(func(fd uintptr) {
			operr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
		}); err != nil {
			return err
		}
		return operr
	}
}
