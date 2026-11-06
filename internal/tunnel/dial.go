package tunnel

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// dialContext resolves host and dials the real destination. If host is
// an IP literal it dials it directly; otherwise it resolves via the
// exit node's local resolver — which is exactly what makes the egress
// come from the exit node's public IP (PRD §12).
func dialContext(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if port == 0 {
		port = 443
	}
	d := &net.Dialer{}
	if ip := net.ParseIP(host); ip != nil {
		return d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))))
	}
	addrs, err := (&net.Resolver{}).LookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("tunnel: resolve %q: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("tunnel: no addresses for %q", host)
	}
	var lastErr error
	for _, a := range addrs {
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(a, strconv.Itoa(int(port))))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
