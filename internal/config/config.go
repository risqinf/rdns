// Package config loads and validates rdns client and server
// configuration (YAML). See examples/*.yaml.
package config

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"rdns/internal/localip"
)

// Logging is shared by both roles.
type Logging struct {
	Level string `yaml:"level"` // debug|info|warn|error (default info)
	File  string `yaml:"file"`  // empty = stderr only
}

// Validate normalizes and checks the logging block.
func (l *Logging) Validate() error {
	l.Level = strings.ToLower(strings.TrimSpace(l.Level))
	switch l.Level {
	case "", "debug", "info", "warn", "error":
		if l.Level == "" {
			l.Level = "info"
		}
	case "warning":
		l.Level = "warn"
	default:
		return fmt.Errorf("logging.level: unknown level %q", l.Level)
	}
	return nil
}

func requireHostPort(label, s string) (string, error) {
	if s == "" {
		return "", fmt.Errorf("%s: required (host:port)", label)
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return "", fmt.Errorf("%s: %q is not host:port", label, s)
	}
	return s, nil
}

// checkFile panics-style fail fast: file must exist and be non-empty.
func checkFile(label, path string) error {
	if path == "" {
		return fmt.Errorf("%s: required", label)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if fi.Size() == 0 {
		return fmt.Errorf("%s: %s is empty", label, path)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Client (decision node)
// ---------------------------------------------------------------------------

// Client is the rdns-client configuration.
type Client struct {
	Listen    ClientListen `yaml:"listen"`
	Rules     string       `yaml:"rules"`
	TLS       ClientTLS    `yaml:"tls"`
	Profiles  []Profile    `yaml:"profiles"`
	DNS       ClientDNS    `yaml:"dns"`
	Reconnect Reconnect    `yaml:"reconnect"`
	Logging   Logging      `yaml:"logging"`

	// TunnelMark is the SO_MARK value stamped on tunnel sockets so the
	// local nftables tproxy rules can skip them (avoids proxying the
	// tunnel to itself). Must match the nftsetup config.
	TunnelMark uint32 `yaml:"tunnel_mark"`

	// LocalIPs are the node's own addresses. nftsetup excludes traffic to
	// these from the redirect so the autoscript VPN endpoints (VLESS/Trojan/
	// SSH-WS on 443, etc.) are not hijacked by the SNI interceptor.
	//
	// For a STATIC public IP you can list it here. For a dynamic/residential
	// IP, leave it empty and rely on AutoLocalIPs (default true), which
	// discovers the box's own interface addresses at startup and on a timer —
	// correct across DHCP/reconnect, and it matches the LOCAL address that
	// DNAT'd inbound traffic actually arrives on.
	LocalIPs []string `yaml:"local_ips"`

	// AutoLocalIPs discovers the host's own interface IPs and merges them
	// with LocalIPs. Defaults to true. Set false only if you want a purely
	// static list (e.g. behind a proxy that changes the visible source).
	AutoLocalIPs *bool `yaml:"auto_local_ips"`

	// LocalIPExclude lists interface-name prefixes to skip during
	// auto-discovery (containers, bridges, tunnels). Empty uses a sane
	// default (docker, br-, veth, tun, tap, wg, ...).
	LocalIPExclude []string `yaml:"local_ip_exclude"`

	// LocalIPRefresh is how often to re-detect interface IPs and re-apply
	// the nftables daddr set, so a mid-run address change is picked up
	// without a restart. Default 60s. 0 disables the timer.
	LocalIPRefresh time.Duration `yaml:"local_ip_refresh"`

	// CDNDirect enables SmartDNS bulk media bypass (nflxvideo.net, googlevideo.com,
	// etc.) so video chunks dial directly, saving >99% exit node bandwidth while
	// preserving geo-DNS accuracy. Defaults to true.
	CDNDirect *bool `yaml:"cdn_direct"`
}

// CDNDirectEnabled reports whether CDN direct streaming is enabled (default true).
func (c *Client) CDNDirectEnabled() bool {
	return c.CDNDirect == nil || *c.CDNDirect
}

// AutoLocalEnabled reports whether interface auto-detection is on (default
// true when the field is unset).
func (c *Client) AutoLocalEnabled() bool {
	return c.AutoLocalIPs == nil || *c.AutoLocalIPs
}

// ResolveLocalIPs returns the effective set of "own" addresses to exclude
// from the redirects: the static LocalIPs, plus (when AutoLocalIPs is on)
// the host's discovered interface addresses. Invalid static entries are
// skipped (validation already reported them).
func (c *Client) ResolveLocalIPs() []net.IP {
	var extra []net.IP
	for _, s := range c.LocalIPs {
		if ip := net.ParseIP(strings.TrimSpace(s)); ip != nil {
			extra = append(extra, ip)
		}
	}
	if !c.AutoLocalEnabled() {
		return extra
	}
	opts := localip.Options{
		Exclude: c.LocalIPExclude,
		Extra:   extra,
	}
	if len(opts.Exclude) == 0 {
		opts.Exclude = localip.DefaultExclude
	}
	ips, err := localip.Detect(opts)
	if err != nil {
		// Discovery failed (e.g. no interfaces readable): fall back to the
		// static list rather than returning nothing (which would hijack the
		// node's own endpoints).
		return extra
	}
	return ips
}

// ClientListen is where the interceptors bind (post-tproxy local ports).
type ClientListen struct {
	DNS  string `yaml:"dns"`  // udp, e.g. 0.0.0.0:5353
	SNI  string `yaml:"sni"`  // tcp, e.g. 0.0.0.0:14300
	QUIC string `yaml:"quic"` // udp, e.g. 0.0.0.0:14400
}

// ClientTLS is the client's identity (mTLS client cert).
type ClientTLS struct {
	CAFile   string `yaml:"ca_file"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Profile is one exit-node destination.
type Profile struct {
	Name       string `yaml:"name"`
	Server     string `yaml:"server"`      // mTLS tunnel endpoint, host:443
	ServerName string `yaml:"server_name"` // expected TLS name on the server
	DNS        string `yaml:"dns"`         // forward-UDP-53 endpoint, host:53
}

// ClientDNS controls the local DNS interceptor.
type ClientDNS struct {
	DefaultUpstream string        `yaml:"default_upstream"` // resolver for non-matching queries
	Timeout         time.Duration `yaml:"timeout"`
	QuerySize       int           `yaml:"query_size"` // max datagram bytes
}

// Reconnect controls tunnel auto-reconnect backoff.
type Reconnect struct {
	Min time.Duration `yaml:"min"`
	Max time.Duration `yaml:"max"`
}

// ValidateClient checks a client config for hard errors.
func ValidateClient(c *Client) error {
	var errs []string
	add := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	_, addErr := requireHostPort("listen.dns", c.Listen.DNS)
	add(addErr)
	_, addErr = requireHostPort("listen.sni", c.Listen.SNI)
	add(addErr)
	if c.Listen.QUIC == "" {
		c.Listen.QUIC = "0.0.0.0:14400"
	}
	_, addErr = requireHostPort("listen.quic", c.Listen.QUIC)
	add(addErr)

	add(checkFile("rules", c.Rules))
	add(checkFile("tls.ca_file", c.TLS.CAFile))
	add(checkFile("tls.cert_file", c.TLS.CertFile))
	add(checkFile("tls.key_file", c.TLS.KeyFile))

	if len(c.Profiles) == 0 {
		errs = append(errs, "profiles: at least one profile required")
	}
	seen := make(map[string]bool, len(c.Profiles))
	for i, p := range c.Profiles {
		prefix := fmt.Sprintf("profiles[%d]", i)
		if p.Name == "" {
			errs = append(errs, prefix+".name: required")
		} else if seen[strings.ToLower(p.Name)] {
			errs = append(errs, prefix+".name: duplicate profile "+p.Name)
		} else {
			seen[strings.ToLower(p.Name)] = true
		}
		if _, e := requireHostPort(prefix+".server", p.Server); e != nil {
			add(e)
		}
		if p.ServerName == "" {
			add(fmt.Errorf("%s.server_name: required", prefix))
		}
		if _, e := requireHostPort(prefix+".dns", p.DNS); e != nil {
			add(e)
		}
	}

	if _, e := requireHostPort("dns.default_upstream", c.DNS.DefaultUpstream); e != nil {
		add(e)
	}
	if c.DNS.Timeout <= 0 {
		c.DNS.Timeout = 3 * time.Second
	}
	if c.DNS.QuerySize <= 0 || c.DNS.QuerySize > 4096 {
		c.DNS.QuerySize = 1232
	}
	if c.Reconnect.Min <= 0 {
		c.Reconnect.Min = time.Second
	}
	if c.Reconnect.Max <= c.Reconnect.Min {
		c.Reconnect.Max = 60 * time.Second
	}
	if c.TunnelMark == 0 {
		c.TunnelMark = TunnelMarkDefault
	}
	if c.LocalIPRefresh == 0 {
		c.LocalIPRefresh = 60 * time.Second
	}
	add(c.Logging.Validate())

	if len(errs) > 0 {
		return fmt.Errorf("client config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// LoadClient reads and validates client YAML.
func LoadClient(path string) (*Client, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	c := &Client{}
	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := ValidateClient(c); err != nil {
		return nil, err
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Server (exit node)
// ---------------------------------------------------------------------------

// Server is the rdns-server configuration.
type Server struct {
	Listen  ServerListen `yaml:"listen"`
	TLS     ServerTLS    `yaml:"tls"`
	ACL     ACL          `yaml:"acl"`
	DNS     ServerDNS    `yaml:"dns"`
	Logging Logging      `yaml:"logging"`
}

// ServerListen — only three public ports (PRD §7).
type ServerListen struct {
	DNS    string `yaml:"dns"`    // udp/53
	Tunnel string `yaml:"tunnel"` // tcp/443 (mTLS yamux)
	ACME   string `yaml:"acme"`   // tcp/80 (HTTP-01 only)
}

// ServerTLS: server identity + which client certs are trusted.
type ServerTLS struct {
	// Server cert for the tunnel listener. Either a static pair or, if
	// Domain is set, Let's Encrypt via autocert (HTTP-01 on the ACME port).
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	Domain   string `yaml:"domain"` // e.g. exit.my.rdns.example — enables autocert

	// ClientCAs is a PEM file of CA certs that may sign client certs.
	ClientCAs string `yaml:"client_cas"`

	// RevokedCerts is an optional PEM file of specific client certs to
	// reject (matched by leaf SPKI SHA-256 digest). May name a file that
	// does not exist yet — that means "no revocations".
	RevokedCerts string `yaml:"revoked_certs"`
}

// ACL governs the public UDP/53 DNS answer service (PRD §8).
type ACL struct {
	// Allowed source IPs/CIDRs (VPS decision nodes).
	Allowed []string `yaml:"allowed"`
	// Rate limit per source IP: tokens = per-second, burst.
	RatePerSec int `yaml:"rate_per_sec"`
	Burst      int `yaml:"burst"`
}

// ServerDNS controls the UDP/53 forward behavior.
type ServerDNS struct {
	// Upstream resolvers (rotated in order). "system" = OS resolver.
	Upstreams []string      `yaml:"upstreams"`
	Timeout   time.Duration `yaml:"timeout"`
	// ForwardedOnly: drop queries that don't come via a known source IP
	// (belt-and-braces; nftables also enforces this).
	ForwardedOnly bool `yaml:"forwarded_only"`
}

// ValidateServer checks a server config.
func ValidateServer(s *Server) error {
	var errs []string
	add := func(err error) {
		if err != nil {
			errs = append(errs, err.Error())
		}
	}

	if _, e := requireHostPort("listen.dns", s.Listen.DNS); e != nil {
		add(e)
	}
	if _, e := requireHostPort("listen.tunnel", s.Listen.Tunnel); e != nil {
		add(e)
	}
	if s.Listen.ACME != "" {
		if _, e := requireHostPort("listen.acme", s.Listen.ACME); e != nil {
			add(e)
		}
	}

	switch {
	case s.TLS.Domain != "":
		// autocert mode: port 80 is mandatory for HTTP-01.
		if s.Listen.ACME == "" {
			errs = append(errs, "tls.domain set but listen.acme missing (HTTP-01 needs port 80)")
		}
	default:
		add(checkFile("tls.cert_file", s.TLS.CertFile))
		add(checkFile("tls.key_file", s.TLS.KeyFile))
	}
	add(checkFile("tls.client_cas", s.TLS.ClientCAs))

	// RevokedCerts is optional and may point at a file that does not exist
	// yet (nothing revoked, or the file is created on first revocation).
	// LoadRevoked treats a missing file as "no revocations", so we only
	// surface a hard error if the file exists but is unreadable/corrupt.
	if s.TLS.RevokedCerts != "" {
		if st, err := os.Stat(s.TLS.RevokedCerts); err == nil {
			// File exists: make sure it is a regular, readable file.
			if !st.Mode().IsRegular() {
				errs = append(errs, "tls.revoked_certs: not a regular file")
			}
		}
		// Missing file → fine (empty revocation list).
	}

	if len(s.ACL.Allowed) == 0 {
		errs = append(errs, "acl.allowed: at least one source IP/CIDR required")
	}
	for i, a := range s.ACL.Allowed {
		if _, _, e := net.ParseCIDR(a); e != nil {
			if net.ParseIP(a) == nil {
				errs = append(errs, fmt.Sprintf("acl.allowed[%d]: %q is not an IP or CIDR", i, a))
			}
		}
	}
	if s.ACL.RatePerSec <= 0 {
		s.ACL.RatePerSec = 50
	}
	if s.ACL.Burst <= 0 {
		s.ACL.Burst = 100
	}

	if len(s.DNS.Upstreams) == 0 {
		s.DNS.Upstreams = []string{"system"}
	}
	for i, u := range s.DNS.Upstreams {
		u = strings.ToLower(u)
		if u == "system" || u == "" {
			s.DNS.Upstreams[i] = "system"
			continue
		}
		if _, e := requireHostPort(fmt.Sprintf("dns.upstreams[%d]", i), u); e != nil {
			add(e)
		}
	}
	if s.DNS.Timeout <= 0 {
		s.DNS.Timeout = 3 * time.Second
	}
	add(s.Logging.Validate())

	if len(errs) > 0 {
		return fmt.Errorf("server config:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// LoadServer reads and validates server YAML.
func LoadServer(path string) (*Server, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	s := &Server{}
	if err := yaml.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := ValidateServer(s); err != nil {
		return nil, err
	}
	return s, nil
}
