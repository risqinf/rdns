package snix

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

func TestHTTPHost(t *testing.T) {
	cases := []struct {
		buf  string
		host string
		kind Kind
	}{
		{"GET / HTTP/1.1\r\nHost: bri.co.id:443\r\n\r\n", "bri.co.id", KindHTTP},
		{"POST /x HTTP/1.1\r\nhost: example.com\r\n\r\n", "example.com", KindHTTP},
		{"GET http://iflix.com/a HTTP/1.1\r\n\r\n", "iflix.com", KindHTTP}, // absolute-form
		{"GET / HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n", "2001:db8::1", KindHTTP},
		{"CONNECT host.example:443 HTTP/1.1\r\n\r\n", "host.example", KindHTTP},
		{"GET / HTTP/1.1\r\nX-Other: zzz\r\n\r\n", "", KindHTTP}, // no Host
		{"this is not http\r\n", "", KindUnknown},
	}
	for _, c := range cases {
		r := Detect([]byte(c.buf))
		if r.Kind != c.kind || r.Host != c.host {
			t.Errorf("Detect(%q) = ({%v,%q}); want (%v,%q)", c.buf, r.Kind, r.Host, c.kind, c.host)
		}
		if !r.Complete() {
			t.Errorf("Detect(%q): expected complete head, got incomplete", c.buf)
		}
	}

	// Partial HTTP head (no \r\n\r\n yet) is Incomplete, not a decision.
	if r := Detect([]byte("GET / HTTP/1.1\r\nHost: a.b")); r.Complete() {
		t.Error("partial HTTP head should be Incomplete")
	}
	// Empty input is Incomplete (need more bytes).
	if r := Detect(nil); r.Complete() {
		t.Error("empty input should be Incomplete")
	}
}

func TestDetectedPort(t *testing.T) {
	cases := []struct {
		buf  string
		host string
		port int
	}{
		{"GET / HTTP/1.1\r\nHost: bri.co.id:8443\r\n\r\n", "bri.co.id", 8443},
		{"GET / HTTP/1.1\r\nHost: bri.co.id\r\n\r\n", "bri.co.id", 0}, // no port stated
		{"CONNECT host.example:443 HTTP/1.1\r\n\r\n", "host.example", 443},
		{"GET http://iflix.com:8080/a HTTP/1.1\r\n\r\n", "iflix.com", 8080},
	}
	for _, c := range cases {
		r := Detect([]byte(c.buf))
		if r.Host != c.host || r.Port != c.port {
			t.Errorf("Detect(%q) = (%q,%d); want (%q,%d)", c.buf, r.Host, r.Port, c.host, c.port)
		}
	}
}

func TestTLSPortIs443(t *testing.T) {
	raw := buildClientHello(t, "bri.co.id")
	if r := Detect(raw); r.Port != 443 {
		t.Errorf("TLS Detect port = %d; want 443", r.Port)
	}
}

// buildClientHello performs a real TLS client handshake against a pipe and
// captures the raw ClientHello bytes — exactly what the interceptor sees.
// The handshake is never completed; we only need the first flight.
func buildClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()

	client := tls.Client(a, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
	done := make(chan error, 1)
	go func() { done <- client.Handshake() }()

	// The client's first flight is one TLS record (the ClientHello), so one
	// pipe read captures it whole.
	buf := make([]byte, 4096)
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, rerr := b.Read(buf)
	// Tear down so the blocked handshake goroutine unblocks, then reap it.
	_ = b.Close()
	_ = a.Close()
	<-done

	if rerr != nil || n < 5 || buf[0] != 0x16 {
		t.Fatalf("read ClientHello: n=%d err=%v", n, rerr)
	}
	return buf[:n]
}

func TestTLSSNI(t *testing.T) {
	cases := []struct {
		sni  string
		want string
	}{
		{"bri.co.id", "bri.co.id"},
		{"mobile.iflix.com", "mobile.iflix.com"},
		{"EXAMPLE.COM", "EXAMPLE.COM"}, // case preserved (client-sent)
		{"", ""},                       // no SNI
	}
	for _, c := range cases {
		raw := buildClientHello(t, c.sni)
		r := Detect(raw)
		if r.Kind != KindTLS {
			t.Errorf("sni=%q: kind=%v; want TLS", c.sni, r.Kind)
		}
		if !r.Complete() {
			t.Errorf("sni=%q: full ClientHello should be Complete", c.sni)
		}
		if r.Host != c.want {
			t.Errorf("sni=%q: host=%q; want %q", c.sni, r.Host, c.want)
		}
	}
}

// TestTLSIncomplete ensures a truncated ClientHello is reported Incomplete
// (not a false "no SNI") so the interceptor keeps buffering.
func TestTLSIncomplete(t *testing.T) {
	raw := buildClientHello(t, "full.example.com")
	for _, cut := range []int{6, 10, 40, len(raw) / 2} {
		if r := Detect(raw[:cut]); r.Complete() {
			t.Errorf("truncated to %d: should be Incomplete", cut)
		}
	}
	// Full buffer is Complete with the SNI.
	r := Detect(raw)
	if !r.Complete() || r.Host != "full.example.com" {
		t.Errorf("full = ({%v,%q,%v}); want Complete, full.example.com", r.Kind, r.Host, r.Status)
	}
}
