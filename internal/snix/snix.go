// Package snix extracts the target host from a connection's first bytes,
// without performing a full TLS handshake. It handles:
//
//   - TLS: the SNI (server_name extension) from a ClientHello
//   - Plain HTTP: the Host: header (or absolute-form/CONNECT request-target)
//
// Detection is tri-state so the SNI interceptor can decide when to keep
// reading: Incomplete means "buffer more bytes", Complete means "we have
// the whole request head / ClientHello" (Host may be "" — e.g. no SNI, ECH,
// or an unsupported payload — which the caller treats as "no match →
// direct"). The caller must replay the buffered bytes to the real
// destination, so Detect never consumes them.
package snix

import (
	"bytes"
	"strings"
)

// Kind identifies what the first bytes look like.
type Kind int

const (
	KindUnknown Kind = iota
	KindTLS
	KindHTTP
)

// Status says whether the buffered bytes are complete.
type Status int

const (
	// Incomplete — need more bytes before a decision.
	Incomplete Status = iota
	// Complete — enough bytes to make a (possibly empty-host) decision.
	Complete
)

// Result is the outcome of Detect.
type Result struct {
	Kind   Kind
	Status Status
	Host   string
	// Port is the destination port implied by the payload (TLS → 443;
	// HTTP Host / CONNECT authority → its port, else 80). 0 = unknown.
	// Used as a fallback when SO_ORIGINAL_DST is unavailable (dev mode).
	Port int
}

// Complete reports whether a decision can be made.
func (r Result) Complete() bool { return r.Status == Complete }

// maxHead is the buffer cap before we give up classifying (a request head
// or ClientHello this large is not sane; the interceptor drops the conn).
const maxHead = 16 * 1024

// Detect inspects buf and classifies it, extracting a host where possible.
func Detect(buf []byte) Result {
	if len(buf) == 0 {
		return Result{Kind: KindUnknown, Status: Incomplete}
	}
	switch buf[0] {
	case 0x16: // TLS handshake record
		return parseTLS(buf)
	default:
		if looksLikeHTTP(buf) {
			return detectHTTP(buf)
		}
		// Not HTTP yet — maybe the method arrives over multiple reads.
		if len(buf) < 8 {
			return Result{Kind: KindUnknown, Status: Incomplete}
		}
		// Definitely not TLS/HTTP; treat as opaque, decide now.
		return Result{Kind: KindUnknown, Status: Complete}
	}
}

func looksLikeHTTP(buf []byte) bool {
	line := buf
	if i := bytes.IndexByte(buf, '\n'); i >= 0 {
		line = buf[:i]
	}
	line = bytes.TrimRight(line, "\r")
	m, _ := splitRequestLine(line)
	return validMethod(m)
}

func splitRequestLine(line []byte) (method, target string) {
	parts := strings.SplitN(strings.TrimSpace(string(line)), " ", 3)
	if len(parts) < 1 {
		return "", ""
	}
	method = parts[0]
	if len(parts) > 1 {
		target = parts[1]
	}
	return method, target
}

func validMethod(m string) bool {
	switch m {
	case "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE", "PATCH":
		return true
	}
	return false
}

// detectHTTP needs the full request head (up to \r\n\r\n). Until then it's
// Incomplete; over the cap it's Complete-with-no-host (drop).
func detectHTTP(buf []byte) Result {
	if !bytes.Contains(buf, []byte("\r\n\r\n")) {
		if len(buf) > maxHead {
			return Result{Kind: KindHTTP, Status: Complete} // drop upstream
		}
		return Result{Kind: KindHTTP, Status: Incomplete}
	}
	host, port := httpHost(buf)
	return Result{Kind: KindHTTP, Status: Complete, Host: host, Port: port}
}

// httpHost pulls the Host header (or absolute-form/CONNECT request-target)
// from a buffered HTTP request head. Returns the bare host and the port it
// implies (0 if none stated — the caller defaults to 80).
func httpHost(buf []byte) (string, int) {
	headEnd := bytes.Index(buf, []byte("\r\n\r\n"))
	var head []byte
	if headEnd >= 0 {
		head = buf[:headEnd+4]
	} else {
		head = buf
	}
	firstLine := head
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		firstLine = head[:i]
	}
	method, target := splitRequestLine(firstLine)
	// CONNECT authority form: the target IS host:port (no Host header).
	if method == "CONNECT" && target != "" {
		if h, p, ok := cutHostPort(target); ok {
			return h, atoiPort(p)
		}
	}
	// Absolute-form request-target, e.g. GET http://host/path — Host may be
	// omitted; fall back to the authority.
	if i := strings.Index(target, "://"); i >= 0 {
		rest := target[i+3:]
		if j := strings.IndexAny(rest, "/?#"); j >= 0 {
			rest = rest[:j]
		}
		if h, p, ok := cutHostPort(rest); ok {
			return h, atoiPort(p)
		}
	}
	// Standard Host: header (first match wins).
	for _, line := range bytes.Split(head, []byte("\n")) {
		line = bytes.Trim(line, "\r ")
		if k, v, found := bytes.Cut(line, []byte(":")); found {
			if strings.EqualFold(string(k), "Host") {
				v = bytes.TrimSpace(v)
				if h, p, ok := cutHostPort(string(v)); ok {
					return h, atoiPort(p)
				}
			}
		}
	}
	return "", 0
}

// atoiPort parses a port string to int (0 on empty/invalid).
func atoiPort(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// cutHostPort splits a "host" or "host:port" (IPv6 in brackets allowed)
// and returns the bare host.
func cutHostPort(s string) (host string, _ string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	if s[0] == '[' { // bracketed IPv6
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return s, "", true
		}
		return s[1:end], s[end+1:], true
	}
	// host:port — the port must be all digits.
	if i := strings.LastIndexByte(s, ':'); i > 0 {
		port := s[i+1:]
		if port != "" && isAllDigits(port) {
			return s[:i], port, true
		}
	}
	return s, "", true
}

func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseTLS walks a TLS ClientHello and returns the SNI. It reports
// Incomplete until the full handshake record is buffered.
func parseTLS(buf []byte) Result {
	// TLS record header: type(1) version(2) len(2).
	if len(buf) < 5 {
		return Result{Kind: KindTLS, Status: Incomplete}
	}
	if buf[0] != 0x16 {
		return Result{Kind: KindUnknown, Status: Complete}
	}
	// Handshake header: type(1) length(3). ClientHello body starts at
	// offset 9 (5-byte record header + 4-byte handshake header).
	if len(buf) < 9 || buf[5] != 0x01 { // 0x01 = ClientHello
		return Result{Kind: KindTLS, Status: Incomplete}
	}
	bodyEnd := 9 + int(uint32(buf[6])<<16|uint32(buf[7])<<8|uint32(buf[8]))
	if bodyEnd > len(buf) {
		return Result{Kind: KindTLS, Status: Incomplete}
	}

	// A cursor bound-checked against the ClientHello body.
	p := 9
	take := func(n int) bool {
		if p+n > bodyEnd {
			return false
		}
		p += n
		return true
	}
	// client_version(2) + random(32)
	if !take(2 + 32) {
		return Result{Kind: KindTLS, Status: Incomplete}
	}
	// legacy_session_id: len(1) + n
	if !take(1) {
		return Result{Kind: KindTLS, Status: Incomplete}
	}
	sidLen := int(buf[p-1])
	if !take(sidLen) {
		return Result{Kind: KindTLS, Status: Incomplete}
	}
	// cipher_suites: len(2) + n
	if !take(2) {
		return Result{Kind: KindTLS, Status: Incomplete}
	}
	csLen := int(uint16(buf[p-2])<<8 | uint16(buf[p-1]))
	if !take(csLen) {
		return Result{Kind: KindTLS, Status: Incomplete}
	}
	// compression_methods: len(1) + n
	if !take(1) {
		return Result{Kind: KindTLS, Status: Incomplete}
	}
	cmLen := int(buf[p-1])
	if !take(cmLen) {
		return Result{Kind: KindTLS, Status: Incomplete}
	}
	// extensions (optional)
	if !take(2) {
		return Result{Kind: KindTLS, Status: Complete} // no SNI (absent)
	}
	extLen := int(uint16(buf[p-2])<<8 | uint16(buf[p-1]))
	extEnd := p + extLen
	if extEnd > bodyEnd {
		return Result{Kind: KindTLS, Status: Incomplete}
	}

	host := ""
	for p+4 <= extEnd {
		et := int(uint16(buf[p])<<8 | uint16(buf[p+1]))
		el := int(uint16(buf[p+2])<<8 | uint16(buf[p+3]))
		data := p + 4
		if data+el > extEnd {
			break
		}
		if et == 0x0000 { // server_name
			host = parseSNIBody(buf[data : data+el])
			break
		}
		p = data + el
	}
	// TLS records on the intercepted ports are HTTPS → port 443.
	return Result{Kind: KindTLS, Status: Complete, Host: host, Port: 443}
}

// parseSNIBody parses the server_name extension body and returns the
// first host_name.
func parseSNIBody(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	listLen := int(uint16(b[0])<<8 | uint16(b[1]))
	p := 2
	if p+listLen > len(b) {
		return ""
	}
	for p < p+listLen {
		if p >= len(b) {
			break
		}
		nameType := b[p]
		p++
		if p+2 > len(b) {
			break
		}
		nameLen := int(uint16(b[p])<<8 | uint16(b[p+1]))
		p += 2
		if p+nameLen > len(b) {
			break
		}
		if nameType == 0x00 { // host_name
			return string(b[p : p+nameLen])
		}
		p += nameLen
	}
	return ""
}
