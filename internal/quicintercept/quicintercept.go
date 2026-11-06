// Package quicintercept is the decision node's transparent UDP/443 (QUIC) interceptor (RFC 9001/9000).
//
// Packets are redirected to this interceptor via nftables TPROXY with IP_TRANSPARENT.
//
// Pipeline:
//  1. Check Flow Table (5-tuple and CID-prefix).
//  2. If flow exists: forward to existing target (Jalur A direct socket or Jalur B tunnel stream).
//  3. If new flow:
//     - Extract SNI from QUIC Initial packet (quicx).
//     - If SNI matches rule:
//     Jalur B: relay through matched profile's mTLS yamux stream (with fail-open to Jalur A if tunnel is down).
//     - If SNI does not match or classification is incomplete:
//     Jalur A: transparent pass-through direct dial to original destination.
//  4. Idle flows are evicted after idleTimeout (default 30s).
package quicintercept

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"rdns/internal/cdnbypass"
	"rdns/internal/markdial"
	"rdns/internal/quicx"
	"rdns/internal/rules"
	"rdns/internal/tunnel"
	"rdns/internal/tunnelmgr"
)

// Service is the QUIC/UDP interceptor.
type Service struct {
	log         *slog.Logger
	rules       *rules.Store
	mgr         *tunnelmgr.Manager
	dialer      *markdial.Dialer
	idleTimeout time.Duration
	listenPort  int

	mu     sync.RWMutex
	flows  map[string]*Flow // 5-tuple key: clientAddr -> origDst
	cidMap map[string]*Flow // CID hex -> Flow

	relayed int64
	direct  int64
	cdnDirect bool
}

// SetCDNDirect controls whether bulk media CDNs bypass the tunnel and dial direct.
func (s *Service) SetCDNDirect(enabled bool) {
	s.cdnDirect = enabled
}

// Flow represents one active bidirectional QUIC connection flow.
type Flow struct {
	key          string
	cid          string
	isTunnel     bool
	profile      string
	stream       tunnel.Stream
	directConn   *net.UDPConn
	clientSend   func([]byte) error
	closeSend    func()
	lastActive   time.Time
	mu           sync.Mutex
	closed       bool
	service      *Service
}

// New builds a new QUIC interceptor Service.
func New(log *slog.Logger, rs *rules.Store, mgr *tunnelmgr.Manager, dialer *markdial.Dialer, idleTimeout time.Duration) *Service {
	if log == nil {
		log = slog.Default()
	}
	if idleTimeout <= 0 {
		idleTimeout = 30 * time.Second
	}
	return &Service{
		log:         log,
		rules:       rs,
		mgr:         mgr,
		dialer:      dialer,
		idleTimeout: idleTimeout,
		flows:       make(map[string]*Flow),
		cidMap:      make(map[string]*Flow),
	}
}

// Stats returns counters for relayed vs direct flows.
func (s *Service) Stats() (relayed, direct int64) {
	return atomic.LoadInt64(&s.relayed), atomic.LoadInt64(&s.direct)
}

// Serve accepts and processes incoming UDP datagrams on ln until ctx is canceled.
func (s *Service) Serve(ctx context.Context, conn *net.UDPConn) error {
	defer conn.Close()
	go s.janitor(ctx)

	if laddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		s.listenPort = laddr.Port
	}

	// Set IP_TRANSPARENT / IP_RECVORIGDSTADDR on the listener socket
	if sc, err := conn.SyscallConn(); err == nil {
		_ = sc.Control(func(fd uintptr) {
			_ = setTransparent(fd)
		})
	}

	buf := make([]byte, tunnel.MaxDatagramSize)
	oob := make([]byte, 1024)

	for {
		if ctx.Err() != nil {
			return nil
		}
		n, oobn, _, clientAddr, err := conn.ReadMsgUDP(buf, oob)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}

		origIP, origPort := parseOrigDst(oob[:oobn])
		packetData := append([]byte(nil), buf[:n]...)

		go s.handlePacket(ctx, conn, clientAddr, origIP, origPort, packetData)
	}
}

func (s *Service) handlePacket(ctx context.Context, listenerConn *net.UDPConn, clientAddr *net.UDPAddr, origIP net.IP, origPort int, data []byte) {
	if s.listenPort > 0 && origPort == s.listenPort {
		if origIP == nil || origIP.IsLoopback() || origIP.IsUnspecified() {
			// Redirected to self without orig dst cmsg
			origPort = 0
		}
	}
	if origPort == 0 {
		origPort = 443
	}
	if origIP == nil && (clientAddr == nil || clientAddr.IP.IsLoopback()) {
		// Loopback packet with no known target; do not handle to avoid self-dial loop
		return
	}
	origIPStr := "unknown"
	if origIP != nil {
		origIPStr = origIP.String()
	}
	clientAddrStr := "unknown"
	if clientAddr != nil {
		clientAddrStr = clientAddr.String()
	}
	flowKey := fmt.Sprintf("%s->%s:%d", clientAddrStr, origIPStr, origPort)

	// 1. Check existing flow
	s.mu.RLock()
	flow, exists := s.flows[flowKey]
	s.mu.RUnlock()

	if exists {
		flow.touch()
		flow.write(data)
		return
	}

	// 2. New flow: inspect packet
	var cidHex string
	var host string
	info, err := quicx.ParseAndDecryptInitial(data)
	if err == nil && info != nil {
		if len(info.DCID) > 0 {
			cidHex = hex.EncodeToString(info.DCID)
			// Check if connection migrated (CID prefix match)
			s.mu.RLock()
			existingFlow, ok := s.cidMap[cidHex]
			s.mu.RUnlock()
			if ok {
				existingFlow.touch()
				existingFlow.write(data)
				return
			}
		}

		chunks, _ := quicx.ExtractCryptoChunks(info.Payload)
		if len(chunks) > 0 {
			// Try to extract SNI
			for _, c := range chunks {
				if h, err := quicx.ParseClientHelloSNI(c.Data); err == nil && h != "" {
					host = h
					break
				}
			}
		}
	}

	// Create client response sender (spoofing origIP via IP_TRANSPARENT, or fallback)
	clientSend, closeSend := s.newClientSender(clientAddr, origIP, origPort, listenerConn)

	// Decision: Jalur A (pass-through) or Jalur B (tunnel relay)
	profile, matched := "", false
	if host != "" {
		profile, matched = s.rules.Match(host)
		if matched && s.cdnDirect && cdnbypass.IsMediaCDN(host) {
			matched = false
			s.log.Debug("quic: smartdns bulk media cdn bypass (direct)", "host", host, "profile", profile)
		}
	}

	if matched && s.mgr != nil {
		// Jalur B: Match -> Tunnel relay
		st, err := s.mgr.StreamForProto(ctx, profile, tunnel.ProtoUDP, host, uint16(origPort))
		if err == nil {
			flow = &Flow{
				key:        flowKey,
				cid:        cidHex,
				isTunnel:   true,
				profile:    profile,
				stream:     st,
				clientSend: clientSend,
				closeSend:  closeSend,
				lastActive: time.Now(),
				service:    s,
			}
			s.registerFlow(flow)
			atomic.AddInt64(&s.relayed, 1)
			s.log.Debug("quic: tunnel flow established", "host", host, "profile", profile, "key", flowKey)

			// Forward the first packet
			flow.write(data)

			// Pump replies from tunnel stream back to client
			go flow.pumpTunnelReplies()
			return
		}

		// Fail-open: tunnel is down, fallback to Jalur A so app stays connected
		s.log.Warn("quic: tunnel unavailable; fallback to direct pass-through (fail-open)",
			"host", host, "profile", profile, "err", err)
	}

	// Jalur A: Pass-through transparan (dial direct UDP)
	var targetAddr string
	if origIP != nil {
		targetAddr = net.JoinHostPort(origIP.String(), strconv.Itoa(origPort))
	} else if host != "" {
		targetAddr = net.JoinHostPort(host, strconv.Itoa(origPort))
	} else {
		closeSend()
		return
	}
	if s.listenPort > 0 && (targetAddr == fmt.Sprintf("127.0.0.1:%d", s.listenPort) || targetAddr == fmt.Sprintf("0.0.0.0:%d", s.listenPort)) {
		closeSend()
		return
	}
	if origIP != nil && origIP.IsLoopback() && s.listenPort > 0 && origPort == s.listenPort {
		closeSend()
		return
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	directConn, err := s.dialer.DialUDP(dctx, targetAddr)
	cancel()
	if err != nil {
		s.log.Debug("quic: direct dial failed", "target", targetAddr, "err", err)
		closeSend()
		return
	}

	flow = &Flow{
		key:        flowKey,
		cid:        cidHex,
		isTunnel:   false,
		directConn: directConn,
		clientSend: clientSend,
		closeSend:  closeSend,
		lastActive: time.Now(),
		service:    s,
	}
	s.registerFlow(flow)
	atomic.AddInt64(&s.direct, 1)
	s.log.Debug("quic: direct flow established", "target", targetAddr, "host", host, "key", flowKey)

	// Forward the first packet
	flow.write(data)

	// Pump replies from direct target back to client
	go flow.pumpDirectReplies()
}

func (s *Service) registerFlow(f *Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flows[f.key] = f
	if f.cid != "" {
		s.cidMap[f.cid] = f
	}
}

func (f *Flow) touch() {
	f.mu.Lock()
	f.lastActive = time.Now()
	f.mu.Unlock()
}

func (f *Flow) write(data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	if f.isTunnel && f.stream != nil {
		_ = tunnel.WriteDatagram(f.stream, data)
	} else if !f.isTunnel && f.directConn != nil {
		_, _ = f.directConn.Write(data)
	}
}

func (f *Flow) pumpTunnelReplies() {
	defer f.close()
	buf := make([]byte, tunnel.MaxDatagramSize)
	for {
		_ = f.stream.SetReadDeadline(time.Now().Add(f.service.idleTimeout))
		n, err := tunnel.ReadDatagram(f.stream, buf)
		if err != nil {
			break
		}
		if n > 0 {
			f.touch()
			if err := f.clientSend(buf[:n]); err != nil {
				break
			}
		}
	}
}

func (f *Flow) pumpDirectReplies() {
	defer f.close()
	buf := make([]byte, tunnel.MaxDatagramSize)
	for {
		_ = f.directConn.SetReadDeadline(time.Now().Add(f.service.idleTimeout))
		n, err := f.directConn.Read(buf)
		if err != nil {
			break
		}
		if n > 0 {
			f.touch()
			if err := f.clientSend(buf[:n]); err != nil {
				break
			}
		}
	}
}

func (f *Flow) close() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	if f.stream != nil {
		_ = f.stream.Close()
	}
	if f.directConn != nil {
		_ = f.directConn.Close()
	}
	if f.closeSend != nil {
		f.closeSend()
	}
	f.mu.Unlock()

	f.service.mu.Lock()
	delete(f.service.flows, f.key)
	if f.cid != "" {
		delete(f.service.cidMap, f.cid)
	}
	f.service.mu.Unlock()
}

func (s *Service) janitor(ctx context.Context) {
	ticker := time.NewTicker(s.idleTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.RLock()
			var expired []*Flow
			for _, f := range s.flows {
				f.mu.Lock()
				if now.Sub(f.lastActive) > s.idleTimeout {
					expired = append(expired, f)
				}
				f.mu.Unlock()
			}
			s.mu.RUnlock()

			for _, f := range expired {
				f.close()
			}
		}
	}
}

// newClientSender creates a function that writes back to clientAddr.
// In Linux with IP_TRANSPARENT, it binds to origIP:origPort so the client
// sees the reply coming from the intended server.
func (s *Service) newClientSender(clientAddr *net.UDPAddr, origIP net.IP, origPort int, fallback *net.UDPConn) (func([]byte) error, func()) {
	if origIP != nil && origPort > 0 {
		laddr := &net.UDPAddr{IP: origIP, Port: origPort}
		d := net.Dialer{
			LocalAddr: laddr,
			Control: func(network, address string, c syscall.RawConn) error {
				var err error
				_ = c.Control(func(fd uintptr) {
					err = setTransparent(fd)
				})
				return err
			},
		}
		conn, err := d.Dial("udp", clientAddr.String())
		if err == nil {
			return func(b []byte) error {
				_, err := conn.Write(b)
				return err
			}, func() { _ = conn.Close() }
		}
	}

	// Fallback to sending via the listener UDP socket
	return func(b []byte) error {
		_, err := fallback.WriteToUDP(b, clientAddr)
		return err
	}, func() {}
}
