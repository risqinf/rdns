// Command rdns-server is the exit node (PRD §12). It runs on the
// country-VPS (Alpine). It opens EXACTLY three public ports:
//
//	udp/53  → ACL-gated DNS answer service (forwards to local resolver)
//	tcp/443 → mTLS yamux tunnel (relay + egress), LE-cert front (or static)
//	tcp/80  → ACME HTTP-01 challenge only (404 otherwise)
//
// It knows nothing about domain rules (PRD §5) — it just answers DNS and
// relays whatever a verified client asks, with egress from its own IP.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rdns/internal/acl"
	"rdns/internal/acme"
	"rdns/internal/certstore"
	"rdns/internal/config"
	"rdns/internal/dnsanswer"
	"rdns/internal/logging"
	"rdns/internal/tunnel"
)

// version is set at build time.
var version = "dev"

func main() {
	var (
		cfgPath   = flag.String("config", "/etc/rdns/server.yaml", "server config path")
		debugFlag = flag.String("debug", "", "debug verbosity: simple (app-level) | full (wire-level traces)")
		showVer   = flag.Bool("version", false, "print version and exit")
		mintToken = flag.Bool("mint-token", false, "mint a client pairing token (rdns://...) and exit")
		profile   = flag.String("profile", "exit", "profile name for minted token")
		clientIP  = flag.String("client-ip", "", "client IP to bind to token")
		caKeyPath = flag.String("cakey", "/etc/rdns/ca.key", "path to CA key for minting token")
	)
	flag.Parse()
	if *showVer {
		fmt.Println("rdns-server", version)
		return
	}
	if *mintToken {
		cfg, err := config.LoadServer(*cfgPath)
		if err != nil {
			fatal("load config: %v", err)
		}
		if err := mintPairingToken(cfg, *profile, *clientIP, *caKeyPath); err != nil {
			fatal("mint token: %v", err)
		}
		return
	}
	debugMode, err := logging.ParseMode(*debugFlag)
	if err != nil {
		fatal("%v", err)
	}

	cfg, err := config.LoadServer(*cfgPath)
	if err != nil {
		fatal("load config: %v", err)
	}
	log, err := logging.Setup(debugMode, cfg.Logging.Level, cfg.Logging.File)
	if err != nil {
		fatal("logging: %v", err)
	}
	log = log.With("role", "server", "version", version)
	log.Info("rdns-server starting")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- ACL (allowlist + rate limit) ------------------------------------
	a, err := acl.New(cfg.ACL.Allowed, cfg.ACL.RatePerSec, cfg.ACL.Burst, time.Minute)
	if err != nil {
		fatal("build ACL: %v", err)
	}
	log.Info("ACL ready", "allowed", len(cfg.ACL.Allowed),
		"rate_per_sec", cfg.ACL.RatePerSec, "burst", cfg.ACL.Burst)

	// --- Internal CA pool + revocation -----------------------------------
	clientCAs, err := certstore.LoadCertPool(cfg.TLS.ClientCAs)
	if err != nil {
		fatal("load client CAs: %v", err)
	}
	revoked, err := certstore.LoadRevoked(cfg.TLS.RevokedCerts)
	if err != nil {
		fatal("load revocations: %v", err)
	}
	log.Info("cert material loaded", "revoked", revoked.Len())

	// --- Tunnel listener TLS config: autocert OR static -------------------
	var (
		tlsCfg  *tls.Config
		acmeSrv *http.Server
	)
	if cfg.TLS.Domain != "" {
		mgr, err := acme.New(acme.Config{Domain: cfg.TLS.Domain, CacheDir: "/var/lib/rdns/acme"})
		if err != nil {
			fatal("init autocert: %v", err)
		}
		tlsCfg = mgr.TunnelTLS(clientCAs)
		ln80, err := net.Listen("tcp", cfg.Listen.ACME)
		if err != nil {
			fatal("listen acme %s: %v", cfg.Listen.ACME, err)
		}
		acmeSrv = &http.Server{Handler: mgr.HTTPHandler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			log.Info("acme (tcp/80) listening", "addr", cfg.Listen.ACME, "domain", cfg.TLS.Domain)
			if err := acmeSrv.Serve(ln80); err != nil && ctx.Err() == nil {
				log.Error("acme listener stopped", "err", err)
			}
		}()
		// Prefetch the LE cert in the background so it is issued right after
		// the Cloudflare/DNS pointing — no waiting for the first client
		// handshake. Retries until success: if DNS hasn't propagated yet
		// (or the pointing is done after this service starts), it self-heals.
		go func() {
			for {
				if err := mgr.Prefetch(); err != nil {
					log.Warn("acme: cert prefetch failed; retrying in 30s "+
						"(check: A record points to this VPS? port 80 reachable?)",
						"domain", cfg.TLS.Domain, "err", err)
				} else {
					log.Info("acme: certificate issued", "domain", cfg.TLS.Domain)
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(30 * time.Second):
				}
			}
		}()
	} else {
		serverCert, err := certstore.LoadServerCert(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			fatal("load server cert: %v", err)
		}
		tlsCfg = certstore.ServerTLSConfig(serverCert, clientCAs)
	}

	// --- Tunnel listener (tcp/443) ---------------------------------------
	tunLn, err := tls.Listen("tcp", cfg.Listen.Tunnel, tlsCfg)
	if err != nil {
		fatal("listen tunnel %s: %v", cfg.Listen.Tunnel, err)
	}
	mode := "static-cert"
	if cfg.TLS.Domain != "" {
		mode = "autocert(LE)"
	}
	log.Info("tunnel listener", "addr", cfg.Listen.Tunnel, "cert", mode,
		"client_auth", "require+verify")
	go serveTunnel(ctx, log, tunLn, revoked)

	// --- DNS answer service (udp/53) -------------------------------------
	fwd, err := dnsanswer.NewUpstreamForwarder(cfg.DNS.Upstreams)
	if err != nil {
		fatal("build DNS forwarder: %v", err)
	}
	dnsLn, err := net.ListenPacket("udp", cfg.Listen.DNS)
	if err != nil {
		fatal("listen dns %s: %v", cfg.Listen.DNS, err)
	}
	dnsSvc := dnsanswer.New(log, a, fwd, cfg.DNS.Timeout)
	go func() {
		log.Info("dns answer service", "addr", cfg.Listen.DNS, "upstreams", cfg.DNS.Upstreams)
		if err := dnsSvc.Serve(ctx, dnsLn.(*net.UDPConn)); err != nil && ctx.Err() == nil {
			log.Error("dns answer service stopped", "err", err)
		}
	}()

	// --- Periodic stats log ----------------------------------------------
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st := dnsSvc.Stats()
				log.Debug("stats", "dns_total", st.Total, "dns_allowed", st.Allowed,
					"dns_drop_acl", st.DroppedACL, "dns_drop_rate", st.DroppedRate,
					"dns_fwd_fail", st.ForwardFail, "acl_buckets", a.Len())
			}
		}
	}()

	// Report the ports actually listening (static-cert mode has no :80).
	ports := []string{"udp/53", "tcp/443"}
	if cfg.Listen.ACME != "" {
		ports = append(ports, "tcp/80")
	}
	log.Info("rdns-server ready", "public_ports", ports)
	<-ctx.Done()
	log.Info("shutdown signal received; draining")
	if acmeSrv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = acmeSrv.Shutdown(sctx)
		cancel()
	}
	time.Sleep(time.Second) // allow in-flight relays to finish
	log.Info("bye")
}

// serveTunnel accepts mTLS connections and runs a yamux relay session each.
func serveTunnel(ctx context.Context, log *slog.Logger, ln net.Listener, revoked *certstore.Revoked) {
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleTunnelConn(ctx, log, conn, revoked)
	}
}

func handleTunnelConn(ctx context.Context, log *slog.Logger, conn net.Conn, revoked *certstore.Revoked) {
	defer conn.Close()
	// The mTLS handshake (client-cert verify) happened in tls.Listen's
	// Accept. Pull the peer leaf for the application-layer revocation check.
	cn := ""
	if tc, ok := conn.(*tls.Conn); ok {
		if ci := tc.ConnectionState(); len(ci.PeerCertificates) > 0 {
			leaf := ci.PeerCertificates[0]
			cn = leaf.Subject.CommonName
			if revoked.IsRevoked(leaf) {
				log.Warn("tunnel: peer cert REVOKED; dropping", "peer", cn)
				return
			}
		}
	}
	slogCtx := log.With("peer", cn)
	slogCtx.Debug("tunnel: session accepted")
	srv := tunnel.NewServer(ctx, conn, tunnel.ServerConfig{MaxConcurrent: 4096}, slogCtx)
	_ = srv.Start()
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rdns-server: "+format+"\n", args...)
	os.Exit(1)
}

type tokenPayload struct {
	Version     int    `json:"version"`
	ProfileName string `json:"profile_name"`
	ServerAddr  string `json:"server_addr"`
	ServerName  string `json:"server_name"`
	DNSUpstream string `json:"dns_upstream"`
	CACert      string `json:"ca_cert"`
	ClientCert  string `json:"client_cert"`
	ClientKey   string `json:"client_key"`
	ExpiresAt   int64  `json:"expires_at"`
	ClientIP    string `json:"client_ip,omitempty"`
}

func mintPairingToken(cfg *config.Server, profile, clientIP, caKeyPath string) error {
	caCertPath := cfg.TLS.ClientCAs
	ca, err := certstore.LoadSigner(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("load CA (%s, %s): %w", caCertPath, caKeyPath, err)
	}

	ttl := 365 * 24 * time.Hour
	clientNodeName := "node-" + profile
	cert, err := ca.SignClient(clientNodeName, ttl)
	if err != nil {
		return fmt.Errorf("sign client cert: %w", err)
	}

	caBytes, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("read ca cert: %w", err)
	}

	serverName := cfg.TLS.Domain
	if serverName == "" {
		serverName = "exit-" + profile
	}

	serverAddr := cfg.Listen.Tunnel
	dnsAddr := cfg.Listen.DNS

	p := tokenPayload{
		Version:     1,
		ProfileName: profile,
		ServerAddr:  serverAddr,
		ServerName:  serverName,
		DNSUpstream: dnsAddr,
		CACert:      string(caBytes),
		ClientCert:  string(certstore.CertPEM(cert.DER)),
		ClientKey:   string(cert.KeyPEM),
		ExpiresAt:   time.Now().Add(ttl).Unix(),
		ClientIP:    clientIP,
	}

	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	token := "rdns://" + base64.StdEncoding.EncodeToString(data)
	fmt.Println(token)
	return nil
}
