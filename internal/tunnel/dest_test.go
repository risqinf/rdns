package tunnel

import (
	"bytes"
	"errors"
	"testing"
)

func TestWriteReadDestRoundTrip(t *testing.T) {
	cases := []struct {
		proto Proto
		host  string
		port  uint16
	}{
		{ProtoTCP, "example.com", 443},
		{ProtoUDP, "example.com", 443},
		{ProtoTCP, "bri.co.id.", 80},     // trailing dot stripped
		{ProtoUDP, "[2001:db8::1]", 443}, // not used on wire, but header len check
		{ProtoTCP, string(bytes.Repeat([]byte("a"), 255)), 8080},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := writeDest(&buf, c.proto, c.host, c.port); err != nil {
			t.Fatalf("writeDest(%d, %q): %v", c.proto, c.host, err)
		}
		proto, host, port, err := readDest(&buf)
		if err != nil {
			t.Fatalf("readDest(%q): %v", c.host, err)
		}
		wantHost := c.host
		if len(wantHost) > 0 && wantHost[len(wantHost)-1] == '.' {
			wantHost = wantHost[:len(wantHost)-1]
		}
		if proto != c.proto || host != wantHost || port != c.port {
			t.Errorf("round-trip %q → (%d,%q,%d); want (%d,%q,%d)", c.host, proto, host, port, c.proto, wantHost, c.port)
		}
	}
}

func TestWriteDestRejects(t *testing.T) {
	var buf bytes.Buffer
	if err := writeDest(&buf, ProtoTCP, "", 443); err == nil {
		t.Error("empty host: want error")
	}
	long := string(bytes.Repeat([]byte("a"), 256))
	if err := writeDest(&buf, ProtoTCP, long, 443); !errors.Is(err, ErrHostTooLong) {
		t.Errorf("256-byte host: want ErrHostTooLong, got %v", err)
	}
	if err := writeDest(&buf, Proto(0x99), "example.com", 443); !errors.Is(err, ErrBadProto) {
		t.Errorf("invalid proto: want ErrBadProto, got %v", err)
	}
}

func TestReadDestRejects(t *testing.T) {
	// Truncated header.
	if _, _, _, err := readDest(bytes.NewReader([]byte{0x01})); err == nil {
		t.Error("truncated header: want error")
	}
	// Bad proto.
	if _, _, _, err := readDest(bytes.NewReader([]byte{0x99, 0x01, 0x01, 0xBB})); !errors.Is(err, ErrBadProto) {
		t.Errorf("bad proto: want ErrBadProto, got %v", err)
	}
	// Zero-length host.
	if _, _, _, err := readDest(bytes.NewReader([]byte{0x01, 0x00, 0x01, 0xBB})); !errors.Is(err, ErrBadHost) {
		t.Errorf("zero-length host: want ErrBadHost, got %v", err)
	}
	// Claim 255 host bytes but supply only 10 → ReadFull must fail.
	short := append([]byte{0x01, 0xFF, 0x01, 0xBB}, bytes.Repeat([]byte("a"), 10)...)
	if _, _, _, err := readDest(bytes.NewReader(short)); err == nil {
		t.Error("claimed 255, sent 10: want error")
	}
}

func TestFramingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	payload := []byte("hello quic world datagram")
	if err := WriteDatagram(&buf, payload); err != nil {
		t.Fatalf("WriteDatagram: %v", err)
	}
	out := make([]byte, 1024)
	n, err := ReadDatagram(&buf, out)
	if err != nil {
		t.Fatalf("ReadDatagram: %v", err)
	}
	if string(out[:n]) != string(payload) {
		t.Errorf("datagram mismatch: got %q, want %q", out[:n], payload)
	}
}
