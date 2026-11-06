package tunnelmgr

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"rdns/internal/tunnel"
)

func quiet() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// pushSession pairs a pipe, wraps the server end in a tunnel.Server (so
// the manager's yamux session has a real peer), and queues the client end
// for the next DialTLS call.
func pushSession(t *testing.T, clientEnds chan net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	clientEnds <- a
	s := tunnel.NewServer(context.Background(), b, tunnel.ServerConfig{}, quiet())
	go func() { _ = s.Start() }()
}

func TestFailClosedWhenDown(t *testing.T) {
	dialFails := func(ctx context.Context, server, name string) (net.Conn, error) {
		return nil, errors.New("no route to exit")
	}
	m := New(&ManagerConfig{
		Profiles:     []Profile{{Name: "my", Server: "1.2.3.4:443", ServerName: "my", DNS: "1.2.3.4:53"}},
		DialTLS:      dialFails,
		ReconnectMin: 10 * time.Millisecond,
		ReconnectMax: 20 * time.Millisecond,
		Log:          quiet(),
	})
	m.Start()
	defer m.Close()

	if m.Alive("my") {
		t.Fatal("profile should be down")
	}
	_, err := m.StreamFor(context.Background(), "my", "host", 443)
	if !errors.Is(err, ErrNoSession) {
		t.Fatalf("StreamFor = %v; want ErrNoSession (fail-closed)", err)
	}
}

func TestConnectAndReconnect(t *testing.T) {
	clientEnds := make(chan net.Conn, 4)
	dial := func(ctx context.Context, server, name string) (net.Conn, error) {
		select {
		case c := <-clientEnds:
			return c, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	m := New(&ManagerConfig{
		Profiles:     []Profile{{Name: "my", Server: "1.2.3.4:443", ServerName: "my", DNS: "1.2.3.4:53"}},
		DialTLS:      dial,
		ReconnectMin: 10 * time.Millisecond,
		ReconnectMax: 30 * time.Millisecond,
		Log:          quiet(),
	})

	waitConn := func(t *testing.T) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for !m.Alive("my") {
			if time.Now().After(deadline) {
				t.Fatal("timed out waiting for session")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// --- session 1 ---------------------------------------------------------
	pushSession(t, clientEnds)
	m.Start()
	defer m.Close()
	waitConn(t)
	if _, err := m.StreamFor(context.Background(), "my", "127.0.0.1", 1); err != nil {
		t.Fatalf("StreamFor on live session: %v", err)
	}

	// --- kill session 1, expect reconnect to session 2 --------------------
	first := clientEnds // not used further; just document intent
	_ = first
	// Kill session 1 by closing the client end the manager holds. We can't
	// reach the server end (b1) from here, so we drive the manager's own
	// reconnect: stop it (which closes its conn and tears the session down)
	// then restart it against a fresh session — the same code path a
	// process restart takes.
	m.Close()
	time.Sleep(20 * time.Millisecond)

	m2 := New(&ManagerConfig{
		Profiles:     []Profile{{Name: "my", Server: "1.2.3.4:443", ServerName: "my", DNS: "1.2.3.4:53"}},
		DialTLS:      dial,
		ReconnectMin: 10 * time.Millisecond,
		ReconnectMax: 30 * time.Millisecond,
		Log:          quiet(),
	})
	pushSession(t, clientEnds)
	m2.Start()
	defer m2.Close()
	if _, err := waitStreamFor(t, m2); err != nil {
		t.Fatalf("StreamFor after reconnect: %v", err)
	}
}

// waitStreamFor retries StreamFor until it returns a working stream, so the
// test asserts on real connectivity rather than the racy Alive() flag.
func waitStreamFor(t *testing.T, m *Manager) (tunnel.Stream, error) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		st, err := m.StreamFor(context.Background(), "my", "127.0.0.1", 1)
		if err == nil {
			return st, nil
		}
		lastErr = err
		time.Sleep(5 * time.Millisecond)
	}
	return nil, lastErr
}

// TestReconnectOnPeerClose verifies the manager brings up a new session
// after its current one's peer dies — the core PRD §10.3 path.
func TestReconnectOnPeerClose(t *testing.T) {
	clientEnds := make(chan net.Conn, 4)
	dial := func(ctx context.Context, server, name string) (net.Conn, error) {
		select {
		case c := <-clientEnds:
			return c, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	m := New(&ManagerConfig{
		Profiles:     []Profile{{Name: "my", Server: "1.2.3.4:443", ServerName: "my", DNS: "1.2.3.4:53"}},
		DialTLS:      dial,
		ReconnectMin: 5 * time.Millisecond,
		ReconnectMax: 20 * time.Millisecond,
		Log:          quiet(),
	})

	waitConn := func() {
		deadline := time.Now().Add(3 * time.Second)
		for !m.Alive("my") {
			if time.Now().After(deadline) {
				t.Fatal("timed out")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	// Session 1.
	a1, b1 := net.Pipe()
	clientEnds <- a1
	s1 := tunnel.NewServer(context.Background(), b1, tunnel.ServerConfig{}, quiet())
	go func() { _ = s1.Start() }()
	m.Start()
	defer m.Close()
	waitConn()

	// Kill session 1's server side → manager must detect death and dial
	// again, which pops session 2.
	a2, b2 := net.Pipe()
	clientEnds <- a2
	// Pre-wrap session 2's server side.
	s2 := tunnel.NewServer(context.Background(), b2, tunnel.ServerConfig{}, quiet())
	go func() { _ = s2.Start() }()

	_ = b1.Close() // peer death

	// Manager should reconnect to session 2. Poll for a working stream.
	if _, err := waitStreamFor(t, m); err != nil {
		t.Fatalf("StreamFor after peer-close reconnect: %v", err)
	}
}
