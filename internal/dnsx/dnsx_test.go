package dnsx

import (
	"testing"

	"github.com/miekg/dns"
)

func packQuery(t *testing.T, name string, qtype uint16) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	buf, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func TestQName(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"bri.co.id", "bri.co.id"},
		{"BRI.CO.ID", "bri.co.id"},                // lowercased
		{"mobile.iflix.com.", "mobile.iflix.com"}, // trailing dot stripped
		{"iflix.com", "iflix.com"},
	}
	for _, c := range cases {
		buf := packQuery(t, c.name, dns.TypeA)
		if got := QName(buf); got != c.want {
			t.Errorf("QName(%q) = %q; want %q", c.name, got, c.want)
		}
	}
}

func TestQNameEdgeCases(t *testing.T) {
	// No question.
	m := new(dns.Msg)
	buf, _ := m.Pack()
	if got := QName(buf); got != "" {
		t.Errorf("no question: got %q; want empty", got)
	}
	// Garbage.
	if got := QName([]byte{0x00, 0x01, 0x02, 0xff}); got != "" {
		t.Errorf("garbage: got %q; want empty", got)
	}
	// Empty.
	if got := QName(nil); got != "" {
		t.Errorf("nil: got %q; want empty", got)
	}
}
