// Package dnsintercept is the decision node's DNS interceptor (PRD §11).
// nftables redirects udp/53 to this local port. For each query it parses
// the QNAME, checks the rule list, and:
//
//   - matched  → forward the raw query to the matched profile's exit node
//     over UDP/53 (the exit node answers with its regional resolver).
//   - unmatched → forward to the local resolver (OS default / configured).
//
// The response is written back to the original client address. This gives
// geo-DNS: a matched domain resolves to the exit region's view of the
// world even though the client sits on a foreign node.
//
// Note: this is the *decision node* side. The *exit node* side is the
// dnsanswer service (ACL-gated), which actually forwards to the regional
// resolver. The client's forward here targets the exit's UDP/53.
package dnsintercept

import (
	"context"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"rdns/internal/dnsx"
	"rdns/internal/logging"
	"rdns/internal/markdial"
	"rdns/internal/rules"
	"rdns/internal/tunnelmgr"
)

// Service is the DNS interceptor.
type Service struct {
	log           *slog.Logger
	rules         *rules.Store
	mgr           *tunnelmgr.Manager
	localDialer   *markdial.Dialer // for forwards (marked, so not re-redirected)
	localUpstream string           // resolver for unmatched queries (host:port)
	timeout       time.Duration
	maxSize       int

	forwarded, local int64 // metrics
}

// New builds a Service. localUpstream is the resolver for unmatched
// queries (e.g. "127.0.0.53:53"); empty means auto-detect the OS default.
func New(log *slog.Logger, rs *rules.Store, mgr *tunnelmgr.Manager, localDialer *markdial.Dialer, localUpstream string, timeout time.Duration) *Service {
	if log == nil {
		log = slog.Default()
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if localUpstream == "" {
		localUpstream = defaultLocalUpstream()
	}
	return &Service{
		log:           log,
		rules:         rs,
		mgr:           mgr,
		localDialer:   localDialer,
		localUpstream: localUpstream,
		timeout:       timeout,
		maxSize:       1500,
	}
}

// Stats returns forward counters.
func (s *Service) Stats() (forwarded, local int64) {
	return atomic.LoadInt64(&s.forwarded), atomic.LoadInt64(&s.local)
}

// Serve blocks answering queries on conn until ctx ends.
func (s *Service) Serve(ctx context.Context, conn *net.UDPConn) error {
	defer conn.Close()
	// ReadFromUDP blocks, so closing the conn is what unblocks it on shutdown.
	go func() { <-ctx.Done(); conn.Close() }()
	buf := make([]byte, s.maxSize)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}
		go s.handleQuery(ctx, conn, append([]byte(nil), buf[:n]...), from)
	}
}

func (s *Service) handleQuery(ctx context.Context, conn *net.UDPConn, data []byte, from *net.UDPAddr) {
	qname := dnsx.QName(data)
	profile, matched := s.rules.Match(qname)
	s.log.Log(ctx, logging.LevelTrace, "dns: query",
		"qname", qname, "bytes", len(data), "from", from.String(), "matched", matched)

	var target string
	if matched {
		if s.mgr == nil {
			return
		}
		dnsAddr, ok := s.mgr.DNSAddr(profile)
		if !ok {
			return
		}
		target = dnsAddr
		atomic.AddInt64(&s.forwarded, 1)
		s.log.Debug("dns: forward", "qname", qname, "profile", profile, "to", target)
	} else {
		// Local resolver (marked dialer so it isn't re-redirected).
		target = s.localUpstream
		atomic.AddInt64(&s.local, 1)
		s.log.Debug("dns: local", "qname", qname, "to", target)
	}

	fctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	// Open a connected UDP socket to the upstream, send the query, read the
	// reply, and copy it back to the original client.
	uc, err := s.localDialer.DialUDP(fctx, target)
	if err != nil {
		s.log.Debug("dns: dial upstream failed", "to", target, "err", err)
		return
	}
	defer uc.Close()
	_ = uc.SetDeadline(time.Now().Add(s.timeout))
	if _, err := uc.Write(data); err != nil {
		s.log.Debug("dns: write upstream failed", "to", target, "err", err)
		return
	}
	reply := make([]byte, s.maxSize)
	n, err := uc.Read(reply)
	if err != nil {
		s.log.Debug("dns: read upstream failed", "to", target, "err", err)
		return
	}
	s.log.Debug("dns: reply from upstream", "from", target, "bytes", n)
	if _, err := conn.WriteToUDP(reply[:n], from); err != nil {
		s.log.Debug("dns: write client failed", "to", from.String(), "err", err)
		return
	}
}

// defaultLocalUpstream reads the first nameserver from /etc/resolv.conf,
// so unmatched queries go to the OS default resolver. Falls back to the
// common systemd-resolved stub.
func defaultLocalUpstream() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 2 && strings.EqualFold(f[0], "nameserver") {
				if !strings.Contains(f[1], ":") {
					f[1] += ":53"
				}
				return f[1]
			}
		}
	}
	return "127.0.0.53:53"
}
