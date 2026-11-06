package tunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"
)

// TestSessionRoundTrip runs the full protocol end-to-end: mTLS (server
// requires + verifies the client cert) over a real TCP loopback socket,
// then relays bytes through one yamux stream to a fake "real
// destination" that the exit node dials.
func TestSessionRoundTrip(t *testing.T) {
	// --- minimal self-signed CA + server + client certs -------------------
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "rdns-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	mkCert := func(cn string, isClient bool, ipSANs []net.IP, dnsSANs []string) *tls.Certificate {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			IPAddresses:  ipSANs,
			DNSNames:     dnsSANs,
		}
		if isClient {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	serverCert := mkCert("rdns-exit", false, []net.IP{net.ParseIP("127.0.0.1")}, nil)
	clientCert := mkCert("node-sg", true, nil, nil)

	// --- exit-node side: mTLS listener on loopback -------------------------
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvAddr := ln.Addr().String()
	srvHost, _, _ := net.SplitHostPort(srvAddr)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		c, err := ln.Accept()
		if err != nil {
			return // test already torn down the listener
		}
		dec := tls.Server(c, &tls.Config{
			Certificates: []tls.Certificate{*serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
		})
		if err := dec.Handshake(); err != nil {
			t.Errorf("server handshake: %v", err)
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		srv := NewServer(ctx, dec, ServerConfig{}, testLogger(t))
		defer srv.Close()
		_ = srv.Start()
	}()

	// --- decision-node side -------------------------------------------------
	cc, err := tls.Dial("tcp", srvAddr, &tls.Config{
		Certificates: []tls.Certificate{*clientCert},
		ServerName:   srvHost,
		RootCAs:      pool,
	})
	if err != nil {
		t.Fatalf("client dial/handshake: %v", err)
	}

	sess, err := NewSession(context.Background(), cc, testLogger(t))
	if err != nil {
		t.Fatal(err)
	}

	// Cleanup runs on every path (including t.Fatal) and — crucially —
	// waits for the server goroutine so it can't log after the test ends.
	defer func() {
		_ = sess.Close()
		_ = cc.Close()
		<-serverDone
	}()

	if !sess.Alive() {
		t.Fatal("session not alive after handshake")
	}
	if _, err := sess.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// --- fake "real destination" the exit node will dial --------------------
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	bh, bpStr, _ := net.SplitHostPort(backend.Addr().String())
	bp, _ := strconv.Atoi(bpStr)

	got := make(chan string, 1)
	go func() {
		c, err := backend.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 512)
		n, _ := c.Read(buf)
		_, _ = c.Write(buf[:n]) // echo
		got <- string(buf[:n])
	}()

	// Open a stream to the fake destination and pump bytes through.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := sess.OpenStream(ctx, bh, uint16(bp))
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	payload := []byte("hello rdns tunnel")
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	gotEcho := make([]byte, len(payload))
	_ = st.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := st.Read(gotEcho)
	if err != nil || n != len(payload) || string(gotEcho) != string(payload) {
		t.Fatalf("echo via tunnel = (%q,%v); want %q", gotEcho[:n], err, payload)
	}

	// The fake backend must have seen the same bytes (server dialed it).
	select {
	case b := <-got:
		if b != string(payload) {
			t.Errorf("backend saw %q; want %q", b, payload)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backend never received relayed bytes")
	}

	if !sess.Alive() {
		t.Error("session dead after successful relay")
	}
}

// testLogger returns a quiet logger so the protocol test doesn't spam output.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}
