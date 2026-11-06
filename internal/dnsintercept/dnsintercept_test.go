package dnsintercept

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"rdns/internal/markdial"
	"rdns/internal/rules"
	"rdns/internal/tunnelmgr"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

func rulesFrom(t *testing.T, m map[string][]string) *rules.Store {
	t.Helper()
	b, _ := json.Marshal(m)
	f := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(f, b, 0600); err != nil {
		t.Fatal(err)
	}
	rs, err := rules.LoadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return rules.NewStore(rs)
}

// fakeDNS answers any query with an NOERROR A record for the query name.
func fakeDNS(t *testing.T) (addr string, hits *int64) {
	t.Helper()
	udp, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp4", udp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	hits = new(int64)
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			atomic.AddInt64(hits, 1)
			resp := echoReply(t, buf[:n])
			if resp != nil {
				_, _ = conn.WriteToUDP(resp, from)
			}
		}
	}()
	return conn.LocalAddr().String(), hits
}

func echoReply(t *testing.T, data []byte) []byte {
	t.Helper()
	var req dnsMsg
	if err := req.Unpack(data); err != nil {
		return nil
	}
	resp := newReply(req)
	b, err := resp.Pack()
	if err != nil {
		return nil
	}
	return b
}

// TestDNSInterceptRouting: matched QNAME → exit DNS (profile), unmatched →
// local resolver. We verify via which fake resolver received the query.
func TestDNSInterceptRouting(t *testing.T) {
	exitAddr, exitHits := fakeDNS(t)   // profile "my" DNS
	localAddr, localHits := fakeDNS(t) // local upstream

	lnUDP, _ := net.ResolveUDPAddr("udp4", "127.0.0.1:0")
	conn, _ := net.ListenUDP("udp4", lnUDP)
	local := conn.LocalAddr().(*net.UDPAddr)

	rs := rulesFrom(t, map[string][]string{"my": {"bri.co.id"}})
	// Manager whose "my" profile DNS = exitAddr; manager itself not needed
	// for the DNS path (that's the SNI/tunnel path), but DNSAddr must work.
	mgr := tunnelmgr.New(&tunnelmgr.ManagerConfig{
		Profiles:     []tunnelmgr.Profile{{Name: "my", Server: "x", ServerName: "x", DNS: exitAddr}},
		DialTLS:      func(ctx context.Context, s, n string) (net.Conn, error) { return nil, nil },
		ReconnectMin: time.Second, ReconnectMax: time.Second, Log: quiet(),
	})
	svc := New(quiet(), rs, mgr, markdial.New(0), localAddr, time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = svc.Serve(ctx, conn) }()

	client := newClient()

	// Matched query (bri.co.id) → exit resolver.
	req1 := query("bri.co.id.")
	if _, err := client.send(ctx, req1, local.String()); err != nil {
		t.Fatalf("matched send: %v", err)
	}
	// Unmatched query (example.com) → local resolver.
	req2 := query("example.com.")
	if _, err := client.send(ctx, req2, local.String()); err != nil {
		t.Fatalf("unmatched send: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	if f, l := svc.Stats(); f != 1 || l != 1 {
		t.Errorf("stats forwarded=%d local=%d; want 1/1", f, l)
	}
	if got := atomic.LoadInt64(exitHits); got != 1 {
		t.Errorf("exit resolver hits=%d; want 1 (matched query)", got)
	}
	if got := atomic.LoadInt64(localHits); got != 1 {
		t.Errorf("local resolver hits=%d; want 1 (unmatched query)", got)
	}
}
