package sniintercept

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"rdns/internal/markdial"
	"rdns/internal/rules"
	"rdns/internal/tunnelmgr"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// rulesFrom writes the map to a temp rules file and loads it.
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

// downManager builds a tunnelmgr whose dial always fails → all profiles
// are down (for fail-closed tests).
func downManager(t *testing.T, profile string) *tunnelmgr.Manager {
	t.Helper()
	m := tunnelmgr.New(&tunnelmgr.ManagerConfig{
		Profiles:     []tunnelmgr.Profile{{Name: profile, Server: "x", ServerName: "x", DNS: "x:53"}},
		DialTLS:      func(ctx context.Context, s, n string) (net.Conn, error) { return nil, context.DeadlineExceeded },
		ReconnectMin: 50 * time.Millisecond,
		ReconnectMax: 100 * time.Millisecond,
		Log:          quiet(),
	})
	m.Start()
	t.Cleanup(m.Close)
	return m
}

// startEcho accepts up to n connections, echoes each back, and records the
// first bytes it saw.
type echoServer struct {
	ln      net.Listener
	saw     chan string
	mu      sync.Mutex
	closers []net.Conn
}

func startEcho(t *testing.T, n int) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	es := &echoServer{ln: ln, saw: make(chan string, n)}
	for i := 0; i < n; i++ {
		go func() {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			es.mu.Lock()
			es.closers = append(es.closers, c)
			es.mu.Unlock()
			defer c.Close()
			buf := make([]byte, 512)
			got := make([]byte, 0, 512)
			for {
				nr, err := c.Read(buf)
				if nr > 0 {
					got = append(got, buf[:nr]...)
				}
				if err != nil || len(got) >= 24 {
					break
				}
			}
			if len(got) > 0 {
				_, _ = c.Write(got)
			}
			es.saw <- string(got)
		}()
	}
	t.Cleanup(func() {
		es.mu.Lock()
		for _, c := range es.closers {
			_ = c.Close()
		}
		es.mu.Unlock()
		_ = ln.Close()
	})
	return es
}

// TestSNIInterceptDirect: an UNMATCHED host is dialed directly — the bytes
// reach the local backend and come back.
func TestSNIInterceptDirect(t *testing.T) {
	es := startEcho(t, 1)
	host, portStr, _ := net.SplitHostPort(es.ln.Addr().String())

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	rs := rulesFrom(t, map[string][]string{"my": {"bri.co.id"}})
	mgr := downManager(t, "my")
	svc := New(quiet(), rs, mgr, markdial.New(0))
	// Fake the pre-redirect destination = the echo backend.
	svc.origDstFn = func(conn net.Conn) (net.IP, int) { return net.ParseIP(host), atoi(portStr) }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = svc.Serve(ctx, ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := "GET / HTTP/1.1\r\nHost: unmatched.example\r\n\r\n"
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp []byte
	buf := make([]byte, 512)
	for len(resp) < len(payload) {
		n, err := c.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	if string(resp) != payload {
		t.Errorf("direct echo = %q; want %q", resp, payload)
	}

	if tunneled, direct := svc.Stats(); direct < 1 || tunneled != 0 {
		t.Errorf("stats tunneled=%d direct=%d; want direct>=1, tunneled=0", tunneled, direct)
	}
	select {
	case saw := <-es.saw:
		if saw == "" {
			t.Error("backend saw nothing")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("backend never saw the direct connection")
	}
}

// TestSNIInterceptHostFallback: when SO_ORIGINAL_DST is unavailable
// (origDstFn returns nil,0 — dev/container mode), the interceptor must dial
// the Host header's host:port, NOT the peer address. Regression test for the
// old bug where the fallback used the client's source IP as the destination.
func TestSNIInterceptHostFallback(t *testing.T) {
	es := startEcho(t, 1)
	host, portStr, _ := net.SplitHostPort(es.ln.Addr().String())

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	rs := rulesFrom(t, map[string][]string{"my": {"bri.co.id"}})
	mgr := downManager(t, "my")
	svc := New(quiet(), rs, mgr, markdial.New(0))
	svc.origDstFn = func(conn net.Conn) (net.IP, int) { return nil, 0 } // "unknown"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = svc.Serve(ctx, ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Host carries the real destination (host:port) — the fallback path.
	payload := "GET / HTTP/1.1\r\nHost: " + host + ":" + portStr + "\r\n\r\n"
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var resp []byte
	buf := make([]byte, 512)
	for len(resp) < len(payload) {
		n, err := c.Read(buf)
		if n > 0 {
			resp = append(resp, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	if string(resp) != payload {
		t.Errorf("host-fallback echo = %q; want %q", resp, payload)
	}
	if _, direct := svc.Stats(); direct < 1 {
		t.Error("expected a direct forward via the host fallback")
	}
}

// TestSNIInterceptFailClosed: a MATCHED host whose profile is DOWN is
// dropped, never leaked direct (PRD §10.3).
func TestSNIInterceptFailClosed(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	rs := rulesFrom(t, map[string][]string{"my": {"bri.co.id"}})
	mgr := downManager(t, "my")
	svc := New(quiet(), rs, mgr, markdial.New(0))
	svc.origDstFn = func(conn net.Conn) (net.IP, int) { return net.ParseIP("127.0.0.1"), 443 }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = svc.Serve(ctx, ln) }()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Plain-HTTP branch: Host bri.co.id matches the rule → tunnel path.
	if _, err := c.Write([]byte("GET / HTTP/1.1\r\nHost: bri.co.id\r\n\r\n")); err != nil {
		t.Fatal(err)
	}

	time.Sleep(100 * time.Millisecond)
	tunneled, direct := svc.Stats()
	if direct != 0 {
		t.Errorf("FAIL-OPEN BUG: direct=%d; a matched host with tunnel down must NOT go direct", direct)
	}
	if tunneled != 0 {
		t.Errorf("tunneled=%d; expected 0 (tunnel down)", tunneled)
	}
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}
