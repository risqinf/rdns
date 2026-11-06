package dnsanswer

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

// UpstreamForwarder forwards queries to a rotating set of upstream
// resolvers. "system" means the OS default resolver (systemd-resolved /
// /etc/resolv.conf) — this is what makes the answer carry the exit
// node's regional DNS (PRD §5).
type UpstreamForwarder struct {
	sys       bool // use OS resolver when no explicit upstream matches
	upstreams []string
	rr        atomic.Uint64 // round-robin cursor
}

// NewUpstreamForwarder builds a forwarder from a list that may contain
// "system". A pure-["system"] (or empty) list uses the OS resolver.
func NewUpstreamForwarder(upstreams []string) (*UpstreamForwarder, error) {
	f := &UpstreamForwarder{}
	for _, u := range upstreams {
		switch strings.ToLower(strings.TrimSpace(u)) {
		case "system", "":
			f.sys = true
		default:
			if _, _, err := net.SplitHostPort(u); err != nil {
				return nil, fmt.Errorf("dnsanswer: bad upstream %q: %w", u, err)
			}
			f.upstreams = append(f.upstreams, u)
		}
	}
	if !f.sys && len(f.upstreams) == 0 {
		f.sys = true // default to system resolver
	}
	return f, nil
}

// Forward sends msg to the next upstream (round-robin), trying the rest
// in order on failure. Returns an error only if all upstreams fail.
func (f *UpstreamForwarder) Forward(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(f.upstreams) > 0 {
		n := len(f.upstreams)
		start := int(f.rr.Add(1) % uint64(n))
		var lastErr error
		for i := 0; i < n; i++ {
			u := f.upstreams[(start+i)%n]
			if resp, err := f.forwardOne(ctx, u, msg); err == nil {
				return resp, nil
			} else {
				lastErr = err
			}
		}
		return nil, lastErr
	}
	return f.forwardSystem(ctx, msg)
}

// forwardSystem forwards via the OS default resolver.
func (f *UpstreamForwarder) forwardSystem(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	resp, err := dns.ExchangeContext(ctx, msg, defaultServer())
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// defaultServer returns the OS default upstream in host:port form,
// read from /etc/resolv.conf (first nameserver).
func defaultServer() string {
	if servers, err := readResolvConf(); err == nil && len(servers) > 0 {
		return servers[0]
	}
	return "127.0.0.53:53" // typical systemd-resolved stub
}

// readResolvConf parses "nameserver" lines from /etc/resolv.conf.
func readResolvConf() ([]string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.EqualFold(fields[0], "nameserver") {
			host := fields[1]
			if !strings.Contains(host, ":") {
				host += ":53"
			}
			out = append(out, host)
		}
	}
	return out, nil
}

func (f *UpstreamForwarder) forwardOne(ctx context.Context, upstream string, msg *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	resp, _, err := c.ExchangeContext(ctx, msg, upstream)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
