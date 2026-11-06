// Command rdns-client is the decision node (PRD §11). It runs on the VPS
// VPN box (Rocky Linux, co-located with autoscript). It:
//
//  1. applies the nftables redirects (udp/53→:5353, tcp/443,80→:14300),
//  2. keeps one mTLS+yamux tunnel per profile to the exit nodes,
//  3. intercepts DNS (udp/53) and SNI/HTTP (tcp/443,80), matches each
//     against the domain rule list, and either relays through the matched
//     profile's tunnel or dials the destination directly.
//
// It needs no inbound ports — all traffic is outbound. Requires CAP_NET-
// ADMIN (nftables) and CAP_NET_RAW/SO_MARK (root) to run the redirects;
// run as root, or grant those caps to the static binary.
package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"rdns/internal/certstore"
	"rdns/internal/config"
	"rdns/internal/dnsintercept"
	"rdns/internal/logging"
	"rdns/internal/markdial"
	"rdns/internal/nftsetup"
	"rdns/internal/quicintercept"
	"rdns/internal/rules"
	"rdns/internal/sniintercept"
	"rdns/internal/tunnelmgr"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var (
		cfgPath   = flag.String("config", "/etc/rdns/client.yaml", "client config path")
		applyNft  = flag.Bool("nft", true, "apply the nftables redirects (needs root/CAP_NET_ADMIN)")
		skipNft   = flag.Bool("no-nft", false, "skip nftables (dev)")
		debugFlag = flag.String("debug", "", "debug verbosity: simple (app-level) | full (wire-level traces)")
		showVer   = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *showVer {
		fmt.Println("rdns-client", version)
		return
	}
	if *skipNft {
		*applyNft = false
	}
	debugMode, err := logging.ParseMode(*debugFlag)
	if err != nil {
		fatal("%v", err)
	}

	cfg, err := config.LoadClient(*cfgPath)
	if err != nil {
		fatal("load config: %v", err)
	}
	log, err := logging.Setup(debugMode, cfg.Logging.Level, cfg.Logging.File)
	if err != nil {
		fatal("logging: %v", err)
	}
	log.Info("rdns-client starting", "version", version)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// SIGHUP is for rule reload, not shutdown.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)

	// --- Rules (with SIGHUP reload) -------------------------------------
	rs, err := rules.LoadFile(cfg.Rules)
	if err != nil {
		fatal("load rules: %v", err)
	}
	ruleStore := rules.NewStore(rs)
	log.Info("rules loaded", "profiles", rs.Profiles(), "domains", rs.Size())
	go reloadOnSignal(ctx, hup, log, cfg.Rules, ruleStore)

	// --- TLS material ----------------------------------------------------
	caPool, err := certstore.LoadCertPool(cfg.TLS.CAFile)
	if err != nil {
		fatal("load CA: %v", err)
	}
	clientCert, err := certstore.LoadServerCert(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		fatal("load client cert: %v", err)
	}

	// --- Marked dialer (excludes our own egress from tproxy) -------------
	dialer := markdial.New(cfg.TunnelMark)

	// --- Tunnel manager (one mTLS+yamux session per profile) -------------
	profiles := make([]tunnelmgr.Profile, 0, len(cfg.Profiles))
	for _, p := range cfg.Profiles {
		profiles = append(profiles, tunnelmgr.Profile{
			Name: p.Name, Server: p.Server, ServerName: p.ServerName, DNS: p.DNS,
		})
	}
	mgr := tunnelmgr.New(&tunnelmgr.ManagerConfig{
		Profiles:     profiles,
		ReconnectMin: cfg.Reconnect.Min,
		ReconnectMax: cfg.Reconnect.Max,
		Log:          log,
		// Build a fresh tls.Config per dial (ServerName varies per profile;
		// tls.Config holds a mutex, so we must not share or copy-by-value it).
		DialTLS: func(ctx context.Context, server, serverName string) (net.Conn, error) {
			tlsCfg := certstore.ClientTLSConfig(caPool, clientCert, serverName)
			dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(dctx, "tcp", server)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(conn, tlsCfg)
			hctx, hcancel := context.WithTimeout(ctx, 15*time.Second)
			defer hcancel()
			if err := tc.HandshakeContext(hctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return tc, nil
		},
	})
	mgr.Start()
	defer mgr.Close()
	log.Info("tunnel manager started", "profiles", len(profiles))

	// --- DNS interceptor (udp) ------------------------------------------
	dnsListener, err := net.ListenPacket("udp", cfg.Listen.DNS)
	if err != nil {
		fatal("listen dns %s: %v", cfg.Listen.DNS, err)
	}
	dnsConn := dnsListener.(*net.UDPConn)
	dnsSvc := dnsintercept.New(log, ruleStore, mgr, dialer, cfg.DNS.DefaultUpstream, cfg.DNS.Timeout)
	go func() {
		if err := dnsSvc.Serve(ctx, dnsConn); err != nil && ctx.Err() == nil {
			log.Error("dns interceptor stopped", "err", err)
		}
	}()
	log.Info("dns interceptor listening", "addr", cfg.Listen.DNS)

	// --- SNI interceptor (tcp) ------------------------------------------
	sniListener, err := net.Listen("tcp", cfg.Listen.SNI)
	if err != nil {
		dnsListener.Close()
		fatal("listen sni %s: %v", cfg.Listen.SNI, err)
	}
	sniSvc := sniintercept.New(log, ruleStore, mgr, dialer)
	sniSvc.SetCDNDirect(cfg.CDNDirectEnabled())
	go func() {
		if err := sniSvc.Serve(ctx, sniListener); err != nil && ctx.Err() == nil {
			log.Error("sni interceptor stopped", "err", err)
		}
	}()
	log.Info("sni interceptor listening", "addr", cfg.Listen.SNI, "cdn_direct", cfg.CDNDirectEnabled())

	// --- QUIC interceptor (udp) -----------------------------------------
	quicListener, err := net.ListenPacket("udp", cfg.Listen.QUIC)
	if err != nil {
		dnsListener.Close()
		sniListener.Close()
		fatal("listen quic %s: %v", cfg.Listen.QUIC, err)
	}
	quicConn := quicListener.(*net.UDPConn)
	quicSvc := quicintercept.New(log, ruleStore, mgr, dialer, 30*time.Second)
	quicSvc.SetCDNDirect(cfg.CDNDirectEnabled())
	go func() {
		if err := quicSvc.Serve(ctx, quicConn); err != nil && ctx.Err() == nil {
			log.Error("quic interceptor stopped", "err", err)
		}
	}()
	log.Info("quic interceptor listening", "addr", cfg.Listen.QUIC, "cdn_direct", cfg.CDNDirectEnabled())

	// --- nftables redirects ---------------------------------------------
	// Apply nftables ONLY AFTER listeners are successfully bound so host traffic
	// is never redirected to dead ports.
	var activeNft *nftsetup.Config
	if *applyNft {
		ips := cfg.ResolveLocalIPs()
		activeNft = nftCfg(cfg, ips)
		if err := nftsetup.Apply(activeNft); err != nil {
			dnsListener.Close()
			sniListener.Close()
			quicListener.Close()
			fatal("apply nftables: %v", err)
		}
		defer func() {
			if err := nftsetup.Unapply(activeNft); err != nil {
				log.Error("failed to unapply nftables", "err", err)
			}
		}()
		log.Info("nftables redirects applied",
			"dns", cfg.Listen.DNS, "sni", cfg.Listen.SNI, "quic", cfg.Listen.QUIC,
			"mark", fmt.Sprintf("0x%x", cfg.TunnelMark),
			"local_ips", ipStrings(ips), "auto", cfg.AutoLocalEnabled())
		// Re-detect + re-apply on a timer so a dynamic/residential address
		// change is picked up without a restart.
		if cfg.LocalIPRefresh > 0 && cfg.AutoLocalEnabled() {
			go refreshNft(ctx, log, cfg)
		}
	} else {
		log.Warn("nftables disabled (dev mode); interceptors will only see locally-redirected traffic")
	}

	// --- Wait for shutdown ----------------------------------------------
	<-ctx.Done()
	log.Info("shutdown signal received; removing nftables redirects")

	// Tear down nftables redirects immediately so host traffic is no longer
	// hijacked while the interceptors and tunnels are shutting down.
	if *applyNft && activeNft != nil {
		if err := nftsetup.Unapply(activeNft); err != nil {
			log.Error("failed to remove nftables redirects", "err", err)
		} else {
			log.Info("nftables redirects removed")
		}
	}

	// Cancellation already closed the interceptors' listeners (they watch
	// ctx), so no new connections are accepted. In-flight relays keep
	// running — Relay doesn't watch ctx — so give them a short grace window
	// before the defers (mgr.Close, listener cleanup) tear the tunnels down.
	time.Sleep(2 * time.Second)
	log.Info("bye")
}

// nftCfg maps the client config + resolved local IPs to an nftables ruleset.
func nftCfg(cfg *config.Client, ips []net.IP) *nftsetup.Config {
	allIPs := append([]net.IP(nil), ips...)
	seen := make(map[string]bool)
	for _, ip := range allIPs {
		seen[ip.String()] = true
	}
	// Also exclude the exit nodes' public IPs from redirection so tunnel dials
	// and DNS queries to the exit nodes can never be looped back into interceptors.
	for _, p := range cfg.Profiles {
		for _, endpoint := range []string{p.Server, p.DNS} {
			host, _, err := net.SplitHostPort(endpoint)
			if err != nil {
				host = endpoint
			}
			if ip := net.ParseIP(host); ip != nil {
				if !seen[ip.String()] {
					seen[ip.String()] = true
					allIPs = append(allIPs, ip)
				}
			}
		}
	}
	return &nftsetup.Config{
		Mark:       cfg.TunnelMark,
		DNSTarget:  localPort(cfg.Listen.DNS),
		SNITarget:  localPort(cfg.Listen.SNI),
		QUICTarget: localPort(cfg.Listen.QUIC),
		LocalIPs:   allIPs,
	}
}

// refreshNft periodically re-detects the host's own IPs and re-applies the
// nftables ruleset when the set changes — so a dynamic/residential address
// (DHCP renew, reconnect, CGNAT re-pool) is tracked without a restart.
// Re-applying an unchanged set is skipped (nft flush+recreate would briefly
// interrupt live connections).
func refreshNft(ctx context.Context, log *slog.Logger, cfg *config.Client) {
	t := time.NewTicker(cfg.LocalIPRefresh)
	defer t.Stop()
	prev := strings.Join(ipStrings(cfg.ResolveLocalIPs()), ",")
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		ips := cfg.ResolveLocalIPs()
		cur := strings.Join(ipStrings(ips), ",")
		if cur == prev {
			continue
		}
		if err := nftsetup.Apply(nftCfg(cfg, ips)); err != nil {
			log.Warn("nftables refresh failed; keeping previous ruleset", "err", err)
			continue
		}
		log.Info("nftables local_ips changed; ruleset refreshed", "old", prev, "new", cur)
		prev = cur
	}
}

// ipStrings renders IPs for logging (stable order).
func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// localPort extracts the port from a host:port listen string.
func localPort(hostport string) int {
	_, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		return 0
	}
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
	}
	return port
}

// reloadOnSignal reloads the domain rules on SIGHUP. A bad file leaves the
// current rules in force (fail-safe, never drops to empty).
func reloadOnSignal(ctx context.Context, hup <-chan os.Signal, log *slog.Logger, path string, store *rules.Store) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		}
		rs, err := rules.LoadFile(path)
		if err != nil {
			log.Warn("rule reload failed; keeping old rules", "err", err)
			continue
		}
		store.Swap(rs)
		log.Info("rules reloaded", "profiles", rs.Profiles(), "domains", rs.Size())
	}
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "rdns-client: "+format+"\n", args...)
	os.Exit(1)
}
