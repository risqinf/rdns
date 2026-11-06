//go:build linux

package quicintercept

import (
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func setTransparent(fd uintptr) error {
	// Enable IP_TRANSPARENT so the socket can bind to non-local addresses and receive TPROXY traffic
	if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1); err != nil {
		return err
	}
	// Enable IP_RECVORIGDSTADDR to receive original destination in cmsg
	if err := unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1); err != nil {
		return err
	}
	// Also attempt IPV6_RECVORIGDSTADDR if IPv6 is active
	_ = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
	return nil
}

func parseOrigDst(oob []byte) (net.IP, int) {
	cmsgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, 0
	}
	for _, m := range cmsgs {
		if m.Header.Level == unix.SOL_IP && m.Header.Type == unix.IP_ORIGDSTADDR {
			pp := (*unix.RawSockaddrInet4)(unsafe.Pointer(&m.Data[0]))
			pBytes := (*[2]byte)(unsafe.Pointer(&pp.Port))
			port := int(pBytes[0])<<8 | int(pBytes[1])
			ip := net.IPv4(pp.Addr[0], pp.Addr[1], pp.Addr[2], pp.Addr[3])
			return ip, port
		}
		if m.Header.Level == unix.SOL_IPV6 && m.Header.Type == unix.IPV6_ORIGDSTADDR {
			pp := (*unix.RawSockaddrInet6)(unsafe.Pointer(&m.Data[0]))
			pBytes := (*[2]byte)(unsafe.Pointer(&pp.Port))
			port := int(pBytes[0])<<8 | int(pBytes[1])
			ip := make(net.IP, 16)
			copy(ip, pp.Addr[:])
			return ip, port
		}
	}
	return nil, 0
}
