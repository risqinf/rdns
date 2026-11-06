// Package acl implements the source-IP allowlist + per-IP rate limiter
// for the public UDP/53 DNS answer service (PRD §8). This is the
// application-layer enforcement; nftables provides the outer layer.
//
// Rate limiting is a per-source-IP token bucket:
//
//	allowed = tokens >= 1  (then spend 1)
//	tokens  = min(burst, tokens + (now - last) * rate)
//
// A lazy sweep evicts idle IPs so a spoofed-IP flood can't grow the map
// unboundedly (mitigating the classic DNS amplification vector).
package acl

import (
	"net"
	"sync"
	"time"
)

// ACL is an IP allowlist with per-IP rate limiting. Safe for concurrent
// use.
type ACL struct {
	nets  []*net.IPNet  // allowed networks (single IPs stored as /32 or /128)
	rate  float64       // tokens/sec per IP
	burst float64       // bucket capacity
	evict time.Duration // idle sweep interval for buckets

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New builds an ACL. allowed is a list of IPs or CIDRs. rate is the
// sustained queries/sec per source IP; burst is the allowed spike.
func New(allowed []string, ratePerSec, burst int, evict time.Duration) (*ACL, error) {
	nets := make([]*net.IPNet, 0, len(allowed))
	for _, a := range allowed {
		ipn, err := parseIPOrCIDR(a)
		if err != nil {
			return nil, err
		}
		nets = append(nets, ipn)
	}
	if ratePerSec <= 0 {
		ratePerSec = 50
	}
	if burst <= 0 {
		burst = 100
	}
	if evict <= 0 {
		evict = time.Minute
	}
	return &ACL{
		nets:    nets,
		rate:    float64(ratePerSec),
		burst:   float64(burst),
		evict:   evict,
		buckets: make(map[string]*bucket),
	}, nil
}

func parseIPOrCIDR(s string) (*net.IPNet, error) {
	if _, ipn, err := net.ParseCIDR(s); err == nil {
		return ipn, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		// Normalize bare IPs to a host network. IPv4 → 4-byte /32, IPv6 →
		// 16-byte /128. (DefaultMask() returns a 4-byte mask for an
		// IPv4-in-IPv6 value, which would mismatch the 16-byte IP.)
		if v4 := ip.To4(); v4 != nil {
			return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
	}
	return nil, &net.ParseError{Type: "IP address or CIDR", Text: s}
}

// Allowed reports whether ip is in the allowlist.
func (a *ACL) Allowed(ip net.IP) bool {
	for _, n := range a.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Allow is the full gate for a DNS query from ip: allowlist + rate limit.
// Returns (allowed, reason). Callers log on reject.
func (a *ACL) Allow(ip net.IP, now time.Time) (bool, string) {
	if !a.Allowed(ip) {
		return false, "ip-not-allowed"
	}
	return a.allowRate(ip, now), ""
}

func (a *ACL) allowRate(ip net.IP, now time.Time) bool {
	key := ip.String()
	a.mu.Lock()
	defer a.mu.Unlock()

	b := a.buckets[key]
	if b == nil {
		// Fresh source starts with a full bucket, so it can burst up to
		// `burst` immediately, then drains at `rate`/sec.
		b = &bucket{tokens: a.burst, last: now}
		a.buckets[key] = b
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * a.rate
			if b.tokens > a.burst {
				b.tokens = a.burst
			}
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Sweep evicts buckets idle longer than the configured interval. Call
// periodically (e.g. from a ticker in the DNS handler).
func (a *ACL) Sweep(now time.Time) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for k, b := range a.buckets {
		if now.Sub(b.last) > a.evict {
			delete(a.buckets, k)
			n++
		}
	}
	return n
}

// Len returns the number of tracked buckets (for metrics/observability).
func (a *ACL) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.buckets)
}
