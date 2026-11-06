// Package certstore loads the mTLS material for both rdns roles
// (PRD §8): the internal CA, per-node client certificates, the server
// certificate, and a simple revocation list.
//
// Revocation model: Go's crypto/tls has no CRL hook for the client-cert
// path, so revocation is enforced in the application layer — after the
// TLS handshake succeeds (chain + signature already verified by the
// server), the exit node checks the peer leaf's SPKI digest against the
// revoked set and drops the connection. Revoking = append the client
// cert to the revocation PEM, restart the server (v1).
package certstore

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// ErrNoCerts — a PEM file contained no usable certificates.
var ErrNoCerts = errors.New("certstore: no PEM certificates found")

// LoadCertPool reads one or more PEM files of CA certificates and returns
// a pool usable for verifying signed leaf certificates.
func LoadCertPool(paths ...string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("certstore: read %s: %w", path, err)
		}
		added := false
		for len(data) > 0 {
			var block *pem.Block
			block, data = pem.Decode(data)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				pool.AddCert(cert)
				added = true
			}
		}
		if !added {
			return nil, fmt.Errorf("%w: %s", ErrNoCerts, path)
		}
	}
	return pool, nil
}

// LoadServerCert reads a leaf cert (chain optional) + private key PEM.
func LoadServerCert(certFile, keyFile string) (*tls.Certificate, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("certstore: read %s: %w", certFile, err)
	}
	var leaf []byte
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			leaf = append(leaf, block.Bytes...)
		}
	}
	if len(leaf) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrNoCerts, certFile)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("certstore: read %s: %w", keyFile, err)
	}
	cert, err := tls.X509KeyPair(CertPEM(leaf), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("certstore: %s+%s: %w", certFile, keyFile, err)
	}
	return &cert, nil
}

// ServerTLSConfig builds the exit-node listener config: requires and
// verifies a client cert against the internal CA.
func ServerTLSConfig(serverCert *tls.Certificate, clientCAs *x509.CertPool) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
	}
}

// ClientTLSConfig builds the decision-node dial config: presents the node
// client cert and verifies the exit node against the internal CA.
func ClientTLSConfig(caPool *x509.CertPool, clientCert *tls.Certificate, serverName string) *tls.Config {
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ServerName:   serverName,
		Certificates: []tls.Certificate{*clientCert},
		RootCAs:      caPool,
	}
}

// Revoked is a set of revoked client certificates, matched by leaf
// SPKI SHA-256 digest (stable across re-encoding).
type Revoked struct {
	digests map[[32]byte]string // digest → reason/subject for logging
}

// LoadRevoked reads a PEM of specific client certificates to reject.
// An empty or missing file means "no revocations".
func LoadRevoked(path string) (*Revoked, error) {
	r := &Revoked{digests: make(map[[32]byte]string)}
	if path == "" {
		return r, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return r, nil
		}
		return nil, fmt.Errorf("certstore: read %s: %w", path, err)
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("certstore: revoked %s: %w", path, err)
		}
		d := spkiDigest(cert)
		r.digests[d] = cert.Subject.CommonName
	}
	return r, nil
}

// IsRevoked reports whether leaf (the TLS peer's leaf cert) is on the
// revoked list.
func (r *Revoked) IsRevoked(leaf *x509.Certificate) bool {
	if r == nil || leaf == nil {
		return false
	}
	_, ok := r.digests[spkiDigest(leaf)]
	return ok
}

// Len returns the number of revoked certificates.
func (r *Revoked) Len() int { return len(r.digests) }

// spkiDigest returns the SHA-256 of the leaf's SPKI (the CRL-SCS
// certificate_fingerprint base) — stable across re-encoding.
func spkiDigest(cert *x509.Certificate) [32]byte {
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo)
}
