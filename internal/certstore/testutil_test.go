package certstore

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"
)

func loadFirstCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			return c
		}
	}
	t.Fatal("no certificate in " + path)
	return nil
}

func parseCert(der []byte) (*x509.Certificate, error) {
	return x509.ParseCertificate(der)
}

func x509VerifyOpts(rootCAs *x509.CertPool) x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:       rootCAs,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
}
