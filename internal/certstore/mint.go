package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// Cert is one minted key/cert pair.
type Cert struct {
	CommonName string
	DER        []byte // leaf cert
	KeyPEM     []byte // PKCS#8 private key
}

// CA is a self-signed certificate authority.
type CA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewCA mints a self-signed CA (ECDSA P-256).
func NewCA(commonName string, ttl time.Duration) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(ttl),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key}, nil
}

// Cert returns the CA certificate.
func (ca *CA) Cert() *x509.Certificate { return ca.cert }

// PEM returns the CA cert as PEM.
func (ca *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// CAKeyPEM returns the CA private key as PKCS#8 PEM.
func CAKeyPEM(ca *CA) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadSigner loads a CA cert + PKCS#8 key from disk so the CLI can mint
// new leaves with the same CA that a deployment already has.
func LoadSigner(caCertPath, caKeyPath string) (*CA, error) {
	if _, err := LoadCertPool(caCertPath); err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	key, err := parseECDSAPrivateKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("CA key: %w", err)
	}
	// We need the actual *x509.Certificate (pool only holds digests), so
	// re-parse the file for the CA cert block.
	certDER, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	// Find the CA cert block (first CERTIFICATE).
	var caDER []byte
	for len(certDER) > 0 {
		var block *pem.Block
		block, certDER = pem.Decode(certDER)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			caDER = block.Bytes
			break
		}
	}
	if caDER == nil {
		return nil, fmt.Errorf("%w: %s", ErrNoCerts, caCertPath)
	}
	parsed, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	if parsed.PublicKey != nil {
		if pub, ok := parsed.PublicKey.(*ecdsa.PublicKey); ok {
			if !pub.Equal(&key.PublicKey) {
				return nil, errors.New("CA key does not match CA certificate")
			}
		}
	}
	return &CA{cert: parsed, key: key}, nil
}

func parseECDSAPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	for len(pemBytes) > 0 {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type != "PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
			continue
		}
		if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if ek, ok := k.(*ecdsa.PrivateKey); ok {
				return ek, nil
			}
		}
		if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return k, nil
		}
	}
	return nil, errors.New("no ECDSA private key found")
}

// SignClient mints a client certificate for a decision node (CN = node
// name, EKU ClientAuth).
func (ca *CA) SignClient(nodeName string, ttl time.Duration) (*Cert, error) {
	return ca.sign(nodeName, ttl, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil, false)
}

// SignServer mints a server certificate for an exit node. SANs may be
// hostnames and/or IPs (at least one required by most TLS clients).
func (ca *CA) SignServer(cn string, ttl time.Duration, dnsNames []string, ips []net.IP) (*Cert, error) {
	return ca.sign(cn, ttl, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, dnsNames, ips, true)
}

func (ca *CA) sign(cn string, ttl time.Duration, ekus []x509.ExtKeyUsage, dnsNames []string, ips []net.IP, isServer bool) (*Cert, error) {
	if len(dnsNames) == 0 && len(ips) == 0 && isServer {
		return nil, errors.New("certstore: server cert needs at least one DNS or IP SAN")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  ekus,
		DNSNames:     dnsNames,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return &Cert{CommonName: cn, DER: der, KeyPEM: keyPEM}, nil
}

// WritePEM writes b to path (0600) creating parent dirs.
func WritePEM(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("certstore: mkdir %s: %w", filepath.Dir(path), err)
	}
	return os.WriteFile(path, b, 0600)
}

// AppendPEM appends b to path (creating it), 0600.
func AppendPEM(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("certstore: mkdir %s: %w", filepath.Dir(path), err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("certstore: open %s: %w", path, err)
	}
	defer f.Close()
	_, err = f.Write(b)
	return err
}

// CertPEM returns a leaf cert as PEM.
func CertPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
