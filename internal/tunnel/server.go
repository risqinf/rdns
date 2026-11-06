package tunnel

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"rdns/internal/logging"
)

// ServerConfig tunes the yamux session on the rdns-server side.
type ServerConfig struct {
	// DialTimeout bounds the real-destination dial per stream (default 10s).
	DialTimeout time.Duration
	// HeaderTimeout bounds reading the stream destination header (default 5s).
	HeaderTimeout time.Duration
	// MaxConcurrent caps simultaneous relays per session; 0 = no cap.
	MaxConcurrent int
}

// Server is one accepted yamux session on the exit node. It accepts
// streams, reads each destination header, dials the real target, and
// relays. It knows nothing about domain rules (PRD §5).
type Server struct {
	cfg    ServerConfig
	log    *slog.Logger
	ymux   *yamux.Session
	closed <-chan struct{} // yamux CloseChan
	ctx    context.Context

	mu     sync.Mutex
	active int
	wg     sync.WaitGroup
	done   bool
}

// NewServer wraps an already-handshaken (mTLS) connection into a yamux
// server session. Start() begins accepting streams (blocks until the
// session or ctx ends).
func NewServer(ctx context.Context, conn net.Conn, cfg ServerConfig, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}
	if cfg.HeaderTimeout <= 0 {
		cfg.HeaderTimeout = 5 * time.Second
	}
	ycfg := yamux.DefaultConfig()
	ycfg.Logger = nil
	ycfg.LogOutput = io.Discard
	ymuxSess, err := yamux.Server(conn, ycfg)
	if err != nil {
		_ = conn.Close()
		// Return a dead server rather than panicking the caller.
		log.Error("tunnel: yamux server init failed", "err", err)
		return &Server{cfg: cfg, log: log, ctx: ctx, closed: make(chan struct{})}
	}
	return &Server{
		cfg: cfg, log: log, ymux: ymuxSess,
		closed: ymuxSess.CloseChan(), ctx: ctx,
	}
}

// Start accepts streams until the session or context ends. It blocks.
func (s *Server) Start() error {
	if s.ymux == nil {
		return io.ErrClosedPipe
	}
	for {
		// AcceptStream in a goroutine so ctx/closed can break the loop
		// even while a peer is streaming nothing.
		type acc struct {
			st  *yamux.Stream
			err error
		}
		ch := make(chan acc, 1)
		go func() {
			st, err := s.ymux.AcceptStream()
			ch <- acc{st, err}
		}()
		select {
		case <-s.ctx.Done():
			return s.finish(s.ctx.Err())
		case <-s.closed:
			return s.finish(nil)
		case a := <-ch:
			if a.err != nil {
				return s.finish(a.err)
			}
			if !s.slot() {
				s.log.Warn("tunnel: relay cap reached; dropping stream")
				_ = a.st.Close()
				continue
			}
			s.wg.Add(1)
			go func(st *yamux.Stream) {
				defer s.wg.Done()
				defer s.unslot()
				s.handleStream(st)
			}(a.st)
		}
	}
}

// finish drains in-flight relays and closes cleanly. Safe to call once.
func (s *Server) finish(cause error) error {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return cause
	}
	s.done = true
	s.mu.Unlock()

	if s.ymux != nil {
		_ = s.ymux.Close()
	}
	s.wg.Wait()
	if cause != nil && !isClosedErr(cause) && s.ctx.Err() == nil {
		s.log.Warn("tunnel: session ended", "cause", cause)
	}
	return cause
}

// slot reserves a relay slot, honoring MaxConcurrent. False = at cap.
func (s *Server) slot() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return false
	}
	if s.cfg.MaxConcurrent > 0 && s.active >= s.cfg.MaxConcurrent {
		return false
	}
	s.active++
	return true
}

func (s *Server) unslot() {
	s.mu.Lock()
	s.active--
	s.mu.Unlock()
}

func (s *Server) handleStream(st *yamux.Stream) {
	_ = st.SetReadDeadline(time.Now().Add(s.cfg.HeaderTimeout))
	proto, host, port, err := readDest(st)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		s.log.Warn("tunnel: bad dest header", "err", err)
		_ = st.Close()
		return
	}

	switch proto {
	case ProtoTCP:
		s.handleTCPStream(st, host, port)
	case ProtoUDP:
		s.handleUDPStream(st, host, port)
	default:
		s.log.Warn("tunnel: unknown proto", "proto", proto)
		_ = st.Close()
	}
}

func (s *Server) handleTCPStream(st *yamux.Stream, host string, port uint16) {
	s.log.Log(s.ctx, logging.LevelTrace, "tunnel: tcp stream accepted", "dest", fmt.Sprintf("%s:%d", host, port))
	dctx, cancel := context.WithTimeout(s.ctx, s.cfg.DialTimeout)
	defer cancel()
	real, err := dialContext(dctx, host, port)
	if err != nil {
		s.log.Warn("tunnel: dial tcp failed", "dest", fmt.Sprintf("%s:%d", host, port), "err", err)
		_ = st.Close()
		return
	}
	defer real.Close()

	toReal, toSt := Relay(st, real)
	s.log.Debug("tunnel: tcp relay done", "dest", fmt.Sprintf("%s:%d", host, port), "to_real", toReal, "to_stream", toSt)
}

func (s *Server) handleUDPStream(st *yamux.Stream, host string, port uint16) {
	dest := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	s.log.Log(s.ctx, logging.LevelTrace, "tunnel: udp stream accepted", "dest", dest)

	targetAddr, err := net.ResolveUDPAddr("udp", dest)
	if err != nil {
		s.log.Warn("tunnel: resolve udp failed", "dest", dest, "err", err)
		_ = st.Close()
		return
	}

	udpConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		s.log.Warn("tunnel: dial udp failed", "dest", dest, "err", err)
		_ = st.Close()
		return
	}
	defer udpConn.Close()

	toUDP, toStream := RelayUDP(st, udpConn, 30*time.Second)
	s.log.Debug("tunnel: udp relay done", "dest", dest, "to_udp", toUDP, "to_stream", toStream)
}

// Active returns in-flight relays (for metrics).
func (s *Server) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Close ends the session and waits for in-flight relays (idempotent).
func (s *Server) Close() error {
	s.mu.Lock()
	if s.done {
		s.mu.Unlock()
		return nil
	}
	s.done = true
	s.mu.Unlock()
	if s.ymux != nil {
		_ = s.ymux.Close()
	}
	s.wg.Wait()
	return nil
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return err == io.EOF || s == "connection reset" || s == "use of closed network connection"
}
