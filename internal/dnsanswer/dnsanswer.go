// Package dnsanswer is the rdns-server's public UDP/53 answer service
// (PRD §12). It accepts DNS queries from authorized decision nodes,
// forwards them to an exit-node-local resolver, and returns the answer.
//
// Security (PRD §8): every query is gated by an ACL (allowlist + per-IP
// rate limit) BEFORE forwarding. Non-authorized or rate-limited queries
// are dropped (not answered) and counted — this is the observable
// "reject count" for the §15 success metric. nftables enforces the same
// policy at the network layer as defense-in-depth.
package dnsanswer

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"rdns/internal/acl"
)

// Forwarder answers a DNS message. Production uses UpstreamForwarder;
// tests inject a stub.
type Forwarder interface {
	Forward(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
}

// Stats is a snapshot of the service counters.
type Stats struct {
	Total       int64 // all datagrams seen
	Allowed     int64 // forwarded to upstream
	DroppedACL  int64 // rejected by allowlist
	DroppedRate int64 // rejected by rate limit
	ForwardFail int64 // upstream errored
}

// Service is the UDP/53 answer service.
type Service struct {
	log       *slog.Logger
	acl       *acl.ACL
	forwarder Forwarder
	timeout   time.Duration
	maxSize   int // max datagram bytes to accept

	total, allowed, dropACL, dropRate, forwardFail atomic.Int64
}

// New builds a Service.
func New(log *slog.Logger, acl *acl.ACL, forwarder Forwarder, timeout time.Duration) *Service {
	if log == nil {
		log = slog.Default()
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Service{log: log, acl: acl, forwarder: forwarder, timeout: timeout, maxSize: 1500}
}

// Stats returns a counter snapshot.
func (s *Service) Stats() Stats {
	return Stats{
		Total: s.total.Load(), Allowed: s.allowed.Load(),
		DroppedACL: s.dropACL.Load(), DroppedRate: s.dropRate.Load(),
		ForwardFail: s.forwardFail.Load(),
	}
}

// Serve blocks handling queries on conn until ctx ends. A background
// ticker sweeps the ACL rate-limit buckets.
func (s *Service) Serve(ctx context.Context, conn *net.UDPConn) error {
	defer conn.Close()
	// ReadFromUDP blocks, so closing the conn is what unblocks it on shutdown.
	go func() { <-ctx.Done(); conn.Close() }()

	sweep := time.NewTicker(30 * time.Second)
	defer sweep.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sweep.C:
				s.acl.Sweep(time.Now())
			}
		}
	}()

	buf := make([]byte, s.maxSize)
	var wg sync.WaitGroup
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil
			}
			return err
		}
		s.total.Add(1)
		if n == 0 {
			continue
		}
		wg.Add(1)
		go func(data []byte, from *net.UDPAddr) {
			defer wg.Done()
			s.handleQuery(ctx, conn, data, from)
		}(append([]byte(nil), buf[:n]...), from)
	}
}

func (s *Service) handleQuery(ctx context.Context, conn *net.UDPConn, data []byte, from *net.UDPAddr) {
	ip := from.IP

	// ACL gate — before we touch the query.
	ok, reason := s.acl.Allow(ip, time.Now())
	if !ok {
		switch reason {
		case "ip-not-allowed":
			s.dropACL.Add(1)
		default:
			s.dropRate.Add(1)
		}
		s.log.Debug("dnsanswer: drop", "from", ip.String(), "reason", reason)
		return
	}

	// Parse + sanity-check it's a query.
	var req dns.Msg
	if err := req.Unpack(data); err != nil {
		s.dropRate.Add(1) // unparseable — treat as noise
		return
	}
	if req.MsgHdr.Response || len(req.Question) == 0 {
		return // not a query we forward
	}

	fctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	resp, err := s.forwarder.Forward(fctx, &req)
	if err != nil || resp == nil {
		s.forwardFail.Add(1)
		s.log.Debug("dnsanswer: forward failed", "from", ip.String(), "err", err)
		return
	}
	s.allowed.Add(1)
	out, err := resp.Pack()
	if err != nil {
		s.forwardFail.Add(1)
		return
	}
	_, _ = conn.WriteToUDP(out, from)
}
