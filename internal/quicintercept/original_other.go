//go:build !linux

package quicintercept

import "net"

func setTransparent(fd uintptr) error {
	return nil
}

func parseOrigDst(oob []byte) (net.IP, int) {
	return nil, 0
}
