package dnsanswer

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"rdns/internal/acl"
)

// stubForwarder echoes a synthetic NOERROR answer with one A record.
type stubForwarder struct {
	gotA   string
	allowA bool
}

func (s *stubForwarder) Forward(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if !s.allowA {
		return nil, context.DeadlineExceeded
	}
	resp := new(dns.Msg)
	resp.SetReply(msg)
	if len(msg.Question) > 0 {
		q := msg.Question[0]
		if s.gotA != "" {
			resp.Answer = append(resp.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
				A:   net.ParseIP(s.gotA),
			})
		}
	}
	return resp, nil
}

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func TestDNSAnswerEndToEnd(t *testing.T) {
	// Bind a UDP "port 53".
	udpAddr, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	local := conn.LocalAddr().(*net.UDPAddr)

	a, _ := acl.New([]string{"127.0.0.1/32"}, 1000, 1000, time.Minute)
	fwd := &stubForwarder{gotA: "203.0.113.99", allowA: true}
	svc := New(quiet(), a, fwd, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = svc.Serve(ctx, conn) }()

	client := new(dns.Client)
	// 1. Authorized query from loopback → should be answered.
	m := new(dns.Msg)
	m.SetQuestion("bri.co.id.", dns.TypeA)
	resp, _, err := client.ExchangeContext(ctx, m, local.String())
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatalf("no answer returned; stats=%+v", svc.Stats())
	}
	if got := resp.Answer[0].(*dns.A).A.String(); got != "203.0.113.99" {
		t.Errorf("answer A = %s; want 203.0.113.99", got)
	}
	st := svc.Stats()
	if st.Total < 1 || st.Allowed < 1 {
		t.Errorf("stats total=%d allowed=%d; want >=1 each", st.Total, st.Allowed)
	}
}

// TestDNSAnswerRejectsUnallowed verifies non-whitelisted sources get no
// answer (fail-closed) and are counted.
func TestDNSAnswerRejectsUnallowed(t *testing.T) {
	udpAddr, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	local := conn.LocalAddr().(*net.UDPAddr)

	// Allowlist is a non-local IP, so loopback queries are rejected.
	a, _ := acl.New([]string{"10.9.8.7/32"}, 1000, 1000, time.Minute)
	fwd := &stubForwarder{allowA: true}
	svc := New(quiet(), a, fwd, time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = svc.Serve(ctx, conn) }()

	// Bounded wait: the server drops the query, so the client's exchange
	// should time out (no answer delivered) rather than return a reply.
	qctx, qcancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer qcancel()
	client := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	_, _, err = client.ExchangeContext(qctx, m, local.String())
	// Expect no response (the server drops it) → client exchange times out
	// or gets no reply. Either way, no answer is delivered.
	_ = err

	// Give the handler a moment to record the drop.
	time.Sleep(50 * time.Millisecond)
	st := svc.Stats()
	if st.DroppedACL < 1 {
		t.Errorf("DroppedACL = %d; want >=1 (stats %+v)", st.DroppedACL, st)
	}
	if st.Allowed != 0 {
		t.Errorf("Allowed = %d; want 0 for unallowed source", st.Allowed)
	}
}
