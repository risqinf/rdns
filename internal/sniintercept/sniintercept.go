// Package sniintercept is the decision node's TCP interceptor (PRD §11).
// nftables redirects tcp/443,80 to this local port; for each connection it
// peeks the SNI (TLS ClientHello) or Host (plain HTTP), checks the rule
// list, and either relays through the matched profile's tunnel stream or
// dials the original destination directly. The original (pre-redirect)
// destination comes from SO_ORIGINAL_DST.
//
// Decision matrix:
//
//	host matched by a rule  → tunnel stream to (host, origPort)  [fail-closed
//	                          if the profile's session is down: conn dropped]
//	host unmatched / ECH /
//	opaque                   → direct dial to (origIP, origPort)  [the
//	                          "everything else goes direct" invariant]
package sniintercept

import (
	"context"
	"log/slog"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"rdns/internal/cdnbypass"
	"rdns/internal/logging"
	"rdns/internal/markdial"
	"rdns/internal/rules"
	"rdns/internal/snix"
	"rdns/internal/tunnel"
	"rdns/internal/tunnelmgr"
)

// Service is the SNI interceptor.
type Service struct {
	log        *slog.Logger
	rules      *rules.Store
	mgr        *tunnelmgr.Manager
	dialer     *markdial.Dialer
	readStart  time.Duration // deadline for the first byte
	headBudget int           // max bytes buffered while classifying

	// origDstFn resolves the pre-redirect destination. Default is the
	// SO_ORIGINAL_DST reader; tests override it for cross-platform runs.
	origDstFn func(net.Conn) (net.IP, int)

	// count of connections relayed vs direct (for metrics/logging).
	tunneled, direct int64
	cdnDirect        bool
}

// SetCDNDirect controls whether bulk media CDNs bypass the tunnel and dial direct.
func (s *Service) SetCDNDirect(enabled bool) {
	s.cdnDirect = enabled
}

// New builds a Service.
func New(log *slog.Logger, rs *rules.Store, mgr *tunnelmgr.Manager, dialer *markdial.Dialer) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		log:        log,
		rules:      rs,
		mgr:        mgr,
		dialer:     dialer,
		readStart:  10 * time.Second,
		headBudget: 128 * 1024,
		origDstFn:  fallbackOrigDst,
	}
}

// fallbackOrigDst reads SO_ORIGINAL_DST (via the platform originalDst).
// When it's unavailable (no tproxy / dev / container without the redirect),
// it returns (nil, 0) — meaning "unknown". The caller then dials the
// SNI/Host name with the port implied by the payload. (The old code fell
// back to the *peer* address, which is the client's source IP — dialing
// that is wrong; this is the correct "unknown" signal.)
func fallbackOrigDst(conn net.Conn) (net.IP, int) {
	if ip, port := originalDst(conn); ip != nil && port > 0 {
		return ip, port
	}
	return nil, 0
}

// Stats returns relay counters.
func (s *Service) Stats() (tunneled, direct int64) {
	return atomic.LoadInt64(&s.tunneled), atomic.LoadInt64(&s.direct)
}

// Serve accepts connections until ctx ends.
func (s *Service) Serve(ctx context.Context, ln net.Listener) error {
	// Accept blocks, so closing the listener is what unblocks it on shutdown.
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handleConn(ctx, conn)
	}
}

func (s *Service) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(60 * time.Second)
		_ = tc.SetNoDelay(true)
	}

	// 1) Classify the first bytes (SNI or Host).
	host, payloadPort, head, err := s.peekHead(ctx, conn)
	if err != nil {
		s.log.Debug("sni: classification failed; dropping", "err", err)
		return
	}
	s.log.Log(ctx, logging.LevelTrace, "sni: classified",
		"host", host, "head_bytes", len(head), "peer", conn.RemoteAddr().String())

	// 2) Original (pre-redirect) destination. On Linux this is
	// SO_ORIGINAL_DST (the real IP:port the client dialed). When it's
	// unavailable (dev / no tproxy), origIP is nil and we fall back to the
	// SNI/Host name + the port implied by the payload.
	origIP, origPort := s.origDstFn(conn)
	if origPort == 0 {
		origPort = payloadPort
	}
	if origPort == 0 {
		origPort = 443 // last resort: the intercepted ports are 443/80
	}

	// 3) Rule lookup.
	profile, matched := s.rules.Match(host)
	if matched && s.cdnDirect && cdnbypass.IsMediaCDN(host) {
		matched = false
		s.log.Debug("sni: smartdns bulk media cdn bypass (direct)", "host", host, "profile", profile)
	}

	var target net.Conn
	switch {
	case matched && s.mgr != nil:
		st, err := s.mgr.StreamFor(ctx, profile, host, uint16(origPort))
		if err != nil {
			// FAIL-CLOSED (PRD §10.3): the profile is down. Drop the conn —
			// never silently leak a matched domain to the origin node.
			s.log.Warn("sni: tunnel unavailable; dropping (fail-closed)",
				"host", host, "profile", profile, "err", err)
			return
		}
		target = st
		atomic.AddInt64(&s.tunneled, 1)
		s.log.Debug("sni: tunnel", "host", host, "profile", profile, "port", origPort)
	default:
		// Direct: dial the original destination. Prefer the pre-redirect IP
		// (already resolved by the client's own DNS); otherwise dial the
		// SNI/Host name (the exit node / OS resolver will resolve it).
		remote := net.JoinHostPort(host, strconv.Itoa(origPort))
		if origIP != nil {
			remote = net.JoinHostPort(origIP.String(), strconv.Itoa(origPort))
		}
		if host == "" && origIP == nil {
			s.log.Debug("sni: no host, no original dst; dropping")
			return
		}
		dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		target, err = s.dialer.DialContext(dctx, "tcp", remote)
		cancel()
		if err != nil {
			s.log.Debug("sni: direct dial failed", "dst", remote, "err", err)
			return
		}
		atomic.AddInt64(&s.direct, 1)
		s.log.Debug("sni: direct", "host", host, "dst", remote)
	}
	defer target.Close()

	// 4) Replay the peeked bytes, then relay both directions.
	if len(head) > 0 {
		if _, err := target.Write(head); err != nil {
			return
		}
	}
	toTarget, toClient := tunnel.Relay(conn, target)
	s.log.Log(ctx, logging.LevelTrace, "sni: relay done",
		"host", host, "to_target", toTarget, "to_client", toClient)
}

// peekHead reads and classifies the connection's first bytes until the
// SNI/Host is known (or the payload is opaque/oversized → empty host).
// Returns (host, port, head, err); port is the destination port implied by
// the payload (443 for TLS, Host/CONNECT port for HTTP, 0 if unknown), used
// as a fallback when SO_ORIGINAL_DST is unavailable. head is the full
// buffered prefix the caller must replay to the real destination.
func (s *Service) peekHead(ctx context.Context, conn net.Conn) (string, int, []byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(s.readStart))
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)

	for {
		n, rerr := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if rerr != nil {
			if n > 0 {
				break // have data, peer closing mid-head
			}
			return "", 0, nil, rerr
		}

		r := snix.Detect(buf)
		if r.Complete() {
			_ = conn.SetReadDeadline(time.Time{}) // clear: relaying now
			return r.Host, r.Port, buf, nil
		}
		// Incomplete — need more. Bound the buffer so a pathological
		// ClientHello can't grow it unboundedly; over budget → treat as
		// opaque (direct) rather than OOM.
		if len(buf) > s.headBudget {
			_ = conn.SetReadDeadline(time.Time{})
			return "", 0, buf, nil
		}
		select {
		case <-ctx.Done():
			return "", 0, nil, ctx.Err()
		default:
		}
	}
	return "", 0, buf, nil
}
