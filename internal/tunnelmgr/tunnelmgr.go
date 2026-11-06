// Package tunnelmgr owns the decision node's persistent mTLS+yamux
// sessions to the exit nodes (PRD §10, §11). One session per profile;
// auto-reconnect with exponential backoff; a health-check keeps the
// session from going stale; and stream access is FAIL-CLOSED — if a
// profile's session is down, its matching traffic is dropped, never
// silently leaked to the origin node (PRD §10.3).
package tunnelmgr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"sync"
	"time"

	"rdns/internal/tunnel"
)

// ErrNoSession — the profile's session is currently down (fail-closed).
var ErrNoSession = errors.New("tunnelmgr: no live session for profile")

// Profile is one exit-node destination.
type Profile struct {
	Name       string
	Server     string // mTLS tunnel endpoint host:443
	ServerName string // TLS server name to verify
	DNS        string // forwarded-DNS endpoint host:53
}

// DialTLS dials an already-verified (caller does mTLS) TCP connection to
// an exit node. The tunnelmgr wraps it in a yamux session.
type DialTLS func(ctx context.Context, server, serverName string) (net.Conn, error)

// Manager keeps one session per profile and reconnects them.
type Manager struct {
	log          *slog.Logger
	dial         DialTLS
	reconnectMin time.Duration
	reconnectMax time.Duration
	profiles     map[string]*profileState
	order        []string
	closeOnce    sync.Once
	ctx          context.Context
	cancel       context.CancelFunc
}

type profileState struct {
	profile Profile
	mu      sync.RWMutex
	sess    *tunnel.Session // current live session, nil when down
}

func (ps *profileState) session() *tunnel.Session {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return ps.sess
}

func (ps *profileState) setSession(s *tunnel.Session) {
	ps.mu.Lock()
	old := ps.sess
	ps.sess = s
	ps.mu.Unlock()
	if old != nil && old != s {
		_ = old.Close()
	}
}

// New builds a Manager.
func New(cfg *ManagerConfig) *Manager {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	if cfg.ReconnectMin <= 0 {
		cfg.ReconnectMin = time.Second
	}
	if cfg.ReconnectMax <= cfg.ReconnectMin {
		cfg.ReconnectMax = 60 * time.Second
	}
	m := &Manager{
		log:          cfg.Log,
		dial:         cfg.DialTLS,
		reconnectMin: cfg.ReconnectMin,
		reconnectMax: cfg.ReconnectMax,
		profiles:     make(map[string]*profileState, len(cfg.Profiles)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.ctx, m.cancel = ctx, cancel
	for _, p := range cfg.Profiles {
		ps := &profileState{profile: p}
		m.profiles[p.Name] = ps
		m.order = append(m.order, p.Name)
	}
	return m
}

// ManagerConfig is the constructor input.
type ManagerConfig struct {
	Profiles     []Profile
	DialTLS      DialTLS
	ReconnectMin time.Duration
	ReconnectMax time.Duration
	Log          *slog.Logger
}

// Start launches the reconnect loop for every profile. It returns
// immediately (the loops run in the background). Use WaitReady to block
// until a profile is connected.
func (m *Manager) Start() {
	for _, name := range m.order {
		go m.run(m.ctx, m.profiles[name])
	}
}

// Close stops all loops and closes all sessions.
func (m *Manager) Close() {
	m.closeOnce.Do(m.cancel)
	for _, name := range m.order {
		if s := m.profiles[name].session(); s != nil {
			_ = s.Close()
		}
	}
}

// StreamFor opens a relay stream to host:port on the profile's session.
// FAIL-CLOSED: returns ErrNoSession (wrapped) if the session is down — the
// caller must drop the connection, never leak it to the origin node
// (PRD §10.3).
//
// There is a narrow race window: a session's peer can die between the
// Alive() check and OpenStream (yamux liveness lags a peer pipe close
// until its recv loop runs). If OpenStream hits that transient
// closed-pipe, we re-check once for a fresh (already-reconnected)
// session and retry. ErrNoSession is NOT retried — a down tunnel stays
// dropped.
func (m *Manager) StreamFor(ctx context.Context, profile, host string, port uint16) (tunnel.Stream, error) {
	return m.StreamForProto(ctx, profile, tunnel.ProtoTCP, host, port)
}

// StreamForProto opens a relay stream for the specified transport protocol (TCP or UDP)
// to host:port on the profile's session.
func (m *Manager) StreamForProto(ctx context.Context, profile string, proto tunnel.Proto, host string, port uint16) (tunnel.Stream, error) {
	ps, ok := m.profiles[profile]
	if !ok {
		return nil, fmt.Errorf("tunnelmgr: unknown profile %q", profile)
	}
	for attempt := 0; attempt < 2; attempt++ {
		sess := ps.session()
		if sess == nil || !sess.Alive() {
			return nil, fmt.Errorf("%w: %s", ErrNoSession, profile)
		}
		st, err := sess.OpenStreamProto(ctx, proto, host, port)
		if err == nil {
			return st, nil
		}
		if !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			return nil, err
		}
		// Transient: the session just died. The run loop is reconnecting;
		// yield a moment, then re-check for a fresh session.
		select {
		case <-time.After(2 * time.Millisecond):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	// Still dead after retry → fail-closed.
	return nil, fmt.Errorf("%w: %s", ErrNoSession, profile)
}

// DNSAddr returns the profile's forwarded-DNS endpoint (host:53).
func (m *Manager) DNSAddr(profile string) (string, bool) {
	ps, ok := m.profiles[profile]
	if !ok {
		return "", false
	}
	return ps.profile.DNS, true
}

// Alive reports whether the profile's session is currently up.
func (m *Manager) Alive(profile string) bool {
	ps, ok := m.profiles[profile]
	if !ok {
		return false
	}
	s := ps.session()
	return s != nil && s.Alive()
}

// WaitReady blocks until the profile is connected or ctx expires.
func (m *Manager) WaitReady(ctx context.Context, profile string) bool {
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		if m.Alive(profile) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
		}
	}
}

// run is the per-profile reconnect loop.
func (m *Manager) run(ctx context.Context, ps *profileState) {
	log := m.log.With("profile", ps.profile.Name)
	backoff := m.reconnectMin
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := m.dial(ctx, ps.profile.Server, ps.profile.ServerName)
		if err != nil {
			log.Warn("tunnelmgr: dial failed", "err", err)
			if sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, m.reconnectMax)
			continue
		}
		sess, err := tunnel.NewSession(ctx, conn, log)
		if err != nil {
			_ = conn.Close()
			log.Warn("tunnelmgr: session init failed", "err", err)
			if sleepCtx(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, m.reconnectMax)
			continue
		}
		ps.setSession(sess)
		log.Info("tunnelmgr: connected")
		backoff = m.reconnectMin // reset on a clean connect

		// Health-check: ping periodically; force-reconnect on failure.
		m.healthPing(ctx, sess, log)

		// Session ended (peer close / error / failed ping).
		ps.setSession(nil)
		log.Info("tunnelmgr: session closed, reconnecting")
		if ctx.Err() != nil {
			return
		}
		// Brief pause before reconnect after a clean close so a flapping
		// server doesn't cause a tight reconnect loop.
		if sleepCtx(ctx, m.reconnectMin) {
			return
		}
	}
}

// healthPing pings the session until it dies or a ping fails.
func (m *Manager) healthPing(ctx context.Context, sess *tunnel.Session, log *slog.Logger) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sess.Closed():
			return
		case <-t.C:
			if _, err := sess.Ping(); err != nil {
				log.Warn("tunnelmgr: health ping failed, forcing reconnect", "err", err)
				_ = sess.Close()
				return
			}
		}
	}
}

// sleepCtx sleeps for d or until ctx ends. Returns true if ctx ended.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return true
	case <-t.C:
		return false
	}
}

// nextBackoff doubles the backoff with jitter, capped at max.
func nextBackoff(cur, max time.Duration) time.Duration {
	next := cur * 2
	if next > max {
		next = max
	}
	// ±20% jitter to avoid thundering herd across nodes.
	jitter := float64(next) * 0.2 * rand.Float64()
	return time.Duration(float64(next) + jitter)
}
