// Package markdial dials sockets stamped with an SO_MARK value.
//
// Why: the client's nftables rules redirect tcp/443,80 → :14300 and
// udp/53 → :5353 for all unmarked traffic. Every OUTBOUND socket the
// rdns-client creates (tunnel to the exit node, DNS forwards to the exit,
// direct dials for non-matching domains) is marked, so nftables skips it —
// otherwise the client would proxy its own egress back into the
// interceptors (infinite loop).
package markdial

import (
	"context"
	"errors"
	"net"
	"time"
)

var errNotUDP = errors.New("markdial: not a UDP conn")

// Dialer dials sockets stamped with the configured mark.
type Dialer struct {
	base net.Dialer
	mark uint32
}

// New builds a Dialer. mark 0 = no marking (dev mode without nftables).
func New(mark uint32) *Dialer {
	return &Dialer{
		base: net.Dialer{
			Timeout: 10 * time.Second,
			Control: control(mark),
		},
		mark: mark,
	}
}

// Mark returns the configured SO_MARK (0 = disabled).
func (d *Dialer) Mark() uint32 { return d.mark }

// DialContext dials a TCP socket with the mark.
func (d *Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.base.DialContext(ctx, network, addr)
}

// DialUDP dials a (connected) UDP socket with the mark.
func (d *Dialer) DialUDP(ctx context.Context, addr string) (*net.UDPConn, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := d.base.DialContext(ctx, "udp", udpAddr.String())
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return nil, errNotUDP
	}
	return uc, nil
}
