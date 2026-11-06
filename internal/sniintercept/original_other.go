//go:build !linux

package sniintercept

import "net"

// originalDst on non-Linux (dev) has no SO_ORIGINAL_DST. Return nil so the
// caller (fallbackOrigDst) uses the peer address. tproxy is Linux-only,
// which is where rdns-client runs in production.
func originalDst(conn net.Conn) (net.IP, int) { return nil, 0 }

var _ net.Addr
