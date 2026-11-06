// Package acme wires Let's Encrypt (HTTP-01) into the rdns-server so the
// public TCP/443 tunnel listener presents a genuine, auto-renewed
// certificate — making the exit node look like an ordinary HTTPS server
// (PRD §6, §13). Port 80 serves ONLY the ACME challenge; everything else
// is 404. Relay never happens on port 80.
//
// The 443 listener uses mTLS: it presents the LE cert (via GetCertificate)
// AND requires/verifies a client cert against the internal CA. So a valid
// public TLS "front" coexists with a strict internal "back" — strangers
// get a TLS client-cert error, not a cert error, and never reach yamux.
package acme

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Config selects autocert mode for the tunnel listener.
type Config struct {
	// Domain is the exit node's public hostname (the LE domain).
	Domain string
	// CacheDir is where autocert stores issued certs (persisted so
	// restarts don't re-challenge; LE allows 5 renewals/hour).
	CacheDir string
}

// Manager owns the autocert machinery.
type Manager struct {
	autocert *autocert.Manager
	domain   string
}

// New builds a Manager. Prompt: AcceptTOS (non-interactive; the domain is
// one you control). HostWhitelist restricts issuance to the single domain.
func New(cfg Config) (*Manager, error) {
	if cfg.Domain == "" {
		return nil, fmt.Errorf("acme: domain required")
	}
	if cfg.CacheDir == "" {
		cfg.CacheDir = "/var/lib/rdns/acme"
	}
	if err := os.MkdirAll(cfg.CacheDir, 0700); err != nil {
		return nil, fmt.Errorf("acme: cache dir %s: %w", cfg.CacheDir, err)
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cfg.CacheDir),
		HostPolicy: autocert.HostWhitelist(cfg.Domain),
		Client:     acmeClient(),
	}
	return &Manager{autocert: m, domain: cfg.Domain}, nil
}

// Prefetch triggers immediate certificate issuance for the domain instead
// of waiting for the first inbound TLS handshake. It performs the HTTP-01
// challenge, so the port-80 handler (HTTPHandler) MUST already be serving
// before this is called. autocert caches the result, so a subsequent
// handshake reuses it. Returns the error from the issuance attempt (the
// caller may log-and-continue: autocert also retries on demand).
func (m *Manager) Prefetch() error {
	_, err := m.autocert.GetCertificate(&tls.ClientHelloInfo{ServerName: m.domain})
	if err != nil {
		return fmt.Errorf("acme: prefetch %s: %w", m.domain, err)
	}
	return nil
}

// TunnelTLS returns the TLS config for the 443 tunnel listener: LE cert
// front (via autocert GetCertificate) + mTLS client verification back.
// clientCAs must be the internal CA pool that signs decision-node certs.
func (m *Manager) TunnelTLS(clientCAs *x509.CertPool) *tls.Config {
	tlsCfg := m.autocert.TLSConfig()
	tlsCfg.MinVersion = tls.VersionTLS12
	tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	tlsCfg.ClientCAs = clientCAs
	return tlsCfg
}

// HTTPHandler is the port-80 handler: serves the ACME challenge, 404s
// everything else. No relay logic, no other paths (PRD §7, §8).
func (m *Manager) HTTPHandler() http.Handler {
	fallback := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	return m.autocert.HTTPHandler(fallback)
}

// acmeClient returns an ACME client. It honors the ACME_SERVER env var
// (e.g. https://pebble.vaporware.dev/dir for local testing) and defaults
// to Let's Encrypt production.
func acmeClient() *acme.Client {
	if v := os.Getenv("ACME_SERVER"); v != "" {
		return &acme.Client{DirectoryURL: v}
	}
	return &acme.Client{} // default: LE production
}
