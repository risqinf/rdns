package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	"rdns/internal/logging"
)

// Stream is one relayed TCP connection inside a session (a yamux stream:
// after the destination header it carries opaque bytes).
type Stream = *yamux.Stream

// Session is one persistent yamux session between a client and one
// exit-node server. Safe for concurrent use. It does NOT reconnect —
// the tunnelmgr does.
type Session struct {
	log    *slog.Logger
	ymux   *yamux.Session
	closed <-chan struct{} // yamux session CloseChan (closed on any shutdown)
}

// NewSession wraps an already-handshaken (mTLS) connection into a yamux
// client session. ctx currently only bounds nothing yet (reserved for
// future stream-open timeouts); the caller still owns closing conn.
func NewSession(ctx context.Context, conn net.Conn, log *slog.Logger) (*Session, error) {
	if log == nil {
		log = slog.Default()
	}
	cfg := yamux.DefaultConfig()
	// Silence yamux internals; rdns logs at its own layer.
	cfg.Logger = nil
	cfg.LogOutput = io.Discard
	ymuxSess, err := yamux.Client(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel: yamux client: %w", err)
	}
	return &Session{log: log, ymux: ymuxSess, closed: ymuxSess.CloseChan()}, nil
}

// Closed is closed when the session ends (peer close, error, or local
// Close). tunnelmgr selects on it to trigger reconnect.
func (s *Session) Closed() <-chan struct{} { return s.closed }

// Alive reports whether the session can still carry streams.
func (s *Session) Alive() bool {
	select {
	case <-s.closed:
		return false
	default:
	}
	return !s.ymux.IsClosed()
}

// Ping round-trips a yamux PING and reports RTT (active health check).
func (s *Session) Ping() (time.Duration, error) {
	if !s.Alive() {
		return 0, io.ErrClosedPipe
	}
	return s.ymux.Ping()
}

// OpenStream opens one relay stream for TCP and writes the destination header.
// It returns io.ErrClosedPipe if the session is dead (fail-closed).
func (s *Session) OpenStream(ctx context.Context, host string, port uint16) (Stream, error) {
	return s.OpenStreamProto(ctx, ProtoTCP, host, port)
}

// OpenStreamProto opens one relay stream with the specified protocol (TCP or UDP)
// and writes the destination header.
func (s *Session) OpenStreamProto(ctx context.Context, proto Proto, host string, port uint16) (Stream, error) {
	if !s.Alive() {
		return nil, io.ErrClosedPipe
	}
	st, err := s.ymux.OpenStream()
	if err != nil {
		if !s.Alive() {
			return nil, io.ErrClosedPipe
		}
		return nil, fmt.Errorf("tunnel: open stream: %w", err)
	}
	if err := writeDest(st, proto, host, port); err != nil {
		_ = st.Close()
		return nil, err
	}
	s.log.Log(ctx, logging.LevelTrace, "tunnel: stream opened", "proto", proto, "dest", fmt.Sprintf("%s:%d", host, port))
	return st, nil
}

// Close tears down the session (idempotent).
func (s *Session) Close() error { return s.ymux.Close() }
