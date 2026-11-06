//go:build linux

package sniintercept

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// SO_ORIGINAL_DST (SOL_IP) returns the destination the packet was actually
// headed for before nftables' `redirect` changed it to our local port. This
// is how the SNI interceptor learns the real port (443/80) and the original
// destination IP.
const soOriginalDst = 80

// originalDst returns the (pre-redirect) destination of conn, or (nil, 0)
// when it can't be determined (caller falls back to the peer address).
func originalDst(conn net.Conn) (net.IP, int) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0
	}
	rc, err := tc.SyscallConn()
	if err != nil {
		return nil, 0
	}
	// sockaddr_in: family(2) port(2, net-order) addr(4) zero(8) = 16 bytes.
	var sa [16]byte
	var l uint32 = 16
	var ip net.IP
	var port int
	var found bool
	var serr error
	// RawConn.Control takes func(fd uintptr) (no error return); capture the
	// getsockopt errno into a local.
	rc.Control(func(fd uintptr) {
		_, _, errno := unix.Syscall6(syscall.SYS_GETSOCKOPT,
			uintptr(fd), unix.SOL_IP, soOriginalDst,
			uintptr(unsafe.Pointer(&sa[0])), uintptr(unsafe.Pointer(&l)), 0)
		if errno != 0 {
			serr = errno
			return
		}
		if sa[0] == 2 { // AF_INET
			port = int(sa[2])<<8 | int(sa[3]) // big-endian port
			ip = net.IPv4(sa[4], sa[5], sa[6], sa[7])
			found = true
		}
	})
	if serr != nil || !found {
		return nil, 0
	}
	return ip, port
}
