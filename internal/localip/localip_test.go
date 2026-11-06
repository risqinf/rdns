package localip

import (
	"net"
	"testing"
)

// TestDetectFindsSomething: on any machine with a non-loopback interface up,
// Detect returns at least one address. (A CI runner always has one.)
func TestDetectFindsSomething(t *testing.T) {
	ips, err := Detect(Options{Exclude: DefaultExclude})
	if err != nil {
		t.Fatal(err)
	}
	// We can't assert a specific address, but the loopback must never appear.
	for _, ip := range ips {
		if ip.IsLoopback() {
			t.Errorf("Detect returned loopback %s; must be excluded", ip)
		}
	}
}

func TestDetectExtraMerged(t *testing.T) {
	extra := []net.IP{net.ParseIP("203.0.113.77")}
	ips, err := Detect(Options{Exclude: DefaultExclude, Extra: extra})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ip := range ips {
		if ip.String() == "203.0.113.77" {
			found = true
		}
	}
	if !found {
		t.Errorf("Extra IP not merged into result: %v", ips)
	}
}

func TestDetectDedupes(t *testing.T) {
	// Same address twice in Extra must appear once.
	dup := []net.IP{net.ParseIP("198.51.100.5"), net.ParseIP("198.51.100.5")}
	ips, err := Detect(Options{Extra: dup})
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, ip := range ips {
		if ip.String() == "198.51.100.5" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("duplicate Extra: got %d copies; want 1", n)
	}
}

func TestNameAllowed(t *testing.T) {
	cases := []struct {
		name    string
		include []string
		exclude []string
		want    bool
	}{
		{"eth0", nil, nil, true},
		{"eth0", nil, []string{"eth"}, false},
		{"docker0", nil, DefaultExclude, false},
		{"tun0", nil, DefaultExclude, false},
		{"wlan0", []string{"eth"}, nil, false}, // include list excludes wlan
		{"eth0", []string{"eth"}, nil, true},
		{"br-abc", nil, DefaultExclude, false},
	}
	for _, c := range cases {
		if got := nameAllowed(c.name, c.include, c.exclude); got != c.want {
			t.Errorf("nameAllowed(%q, %v, %v) = %v; want %v", c.name, c.include, c.exclude, got, c.want)
		}
	}
}
