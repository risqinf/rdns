package certstore

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMintAndLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	caOut := filepath.Join(dir, "ca")
	certs := filepath.Join(dir, "certs")

	// 1. Mint CA.
	ca, err := NewCA("rdns-test-ca", 100*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caKeyPEM, err := CAKeyPEM(ca)
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePEM(caOut+"/ca.crt", ca.PEM()); err != nil {
		t.Fatal(err)
	}
	if err := WritePEM(caOut+"/ca.key", caKeyPEM); err != nil {
		t.Fatal(err)
	}

	// 2. Reload the signer from disk (as the CLI does).
	ca2, err := LoadSigner(caOut+"/ca.crt", caOut+"/ca.key")
	if err != nil {
		t.Fatalf("LoadSigner: %v", err)
	}

	// 3. Mint a client cert + a server cert.
	client, err := ca2.SignClient("node-sg", 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server, err := ca2.SignServer("exit-my", 90*24*time.Hour, []string{"127.0.0.1"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	if err := WritePEM(certs+"/node-sg.crt", CertPEM(client.DER)); err != nil {
		t.Fatal(err)
	}
	if err := WritePEM(certs+"/node-sg.key", client.KeyPEM); err != nil {
		t.Fatal(err)
	}
	if err := WritePEM(certs+"/exit-my.crt", CertPEM(server.DER)); err != nil {
		t.Fatal(err)
	}
	if err := WritePEM(certs+"/exit-my.key", server.KeyPEM); err != nil {
		t.Fatal(err)
	}

	// 4. Load client cert pair — must parse as a valid TLS cert.
	if _, err := LoadServerCert(certs+"/node-sg.crt", certs+"/node-sg.key"); err != nil {
		t.Fatalf("LoadServerCert(client pair): %v", err)
	}

	// 5. CA pool verifies the client cert.
	pool, err := LoadCertPool(caOut + "/ca.crt")
	if err != nil {
		t.Fatal(err)
	}
	leaf := loadFirstCert(t, certs+"/node-sg.crt")
	if _, err := leaf.Verify(x509VerifyOpts(pool)); err != nil {
		t.Errorf("client cert should verify against CA: %v", err)
	}
}

func TestRevocation(t *testing.T) {
	dir := t.TempDir()
	ca, _ := NewCA("rdns-rev-ca", 10*24*time.Hour)
	victim, _ := ca.SignClient("victim-node", 10*24*time.Hour)
	innocent, _ := ca.SignClient("innocent-node", 10*24*time.Hour)

	victimCert, _ := parseCert(victim.DER)
	innocentCert, _ := parseCert(innocent.DER)

	revPath := filepath.Join(dir, "revoked.crt")
	// No revocation file → nothing revoked.
	empty, _ := LoadRevoked("")
	if empty.IsRevoked(victimCert) {
		t.Error("empty revocation list should revoke nothing")
	}
	if empty.Len() != 0 {
		t.Errorf("Len() = %d; want 0", empty.Len())
	}

	// Revoke the victim.
	if err := AppendPEM(revPath, CertPEM(victim.DER)); err != nil {
		t.Fatal(err)
	}
	rev, err := LoadRevoked(revPath)
	if err != nil {
		t.Fatal(err)
	}
	if !rev.IsRevoked(victimCert) {
		t.Error("victim should be revoked")
	}
	if rev.IsRevoked(innocentCert) {
		t.Error("innocent should NOT be revoked")
	}
	if rev.Len() != 1 {
		t.Errorf("Len() = %d; want 1", rev.Len())
	}
}

func TestLoadCertPoolRejects(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.crt")
	if err := os.WriteFile(bad, []byte("not pem\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertPool(bad); err == nil {
		t.Error("non-PEM file: want error")
	}
	missing := filepath.Join(dir, "missing.crt")
	if _, err := LoadCertPool(missing); err == nil {
		t.Error("missing file: want error")
	}
}
