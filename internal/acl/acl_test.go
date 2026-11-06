package acl

import (
	"net"
	"testing"
	"time"
)

func TestAllowed(t *testing.T) {
	a, err := New([]string{"203.0.113.10", "198.51.100.0/24", "2001:db8::/32"}, 100, 100, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.10", true},
		{"198.51.100.42", true}, // in /24
		{"2001:db8::1", true},   // in /32
		{"203.0.113.11", false},
		{"198.51.101.1", false}, // out of /24
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		if got := a.Allowed(net.ParseIP(c.ip)); got != c.want {
			t.Errorf("Allowed(%s) = %v; want %v", c.ip, got, c.want)
		}
	}
}

func TestRateLimit(t *testing.T) {
	a, _ := New([]string{"1.2.3.4"}, 2, 2, time.Minute) // 2/s, burst 2
	ip := net.ParseIP("1.2.3.4")

	t0 := time.Unix(1000, 0)
	// Burst: 2 immediate allowed, 3rd denied.
	if ok, r := a.Allow(ip, t0); !ok {
		t.Fatalf("query 1: want allowed, got %q", r)
	}
	if ok, _ := a.Allow(ip, t0); !ok {
		t.Fatalf("query 2: want allowed, got denied")
	}
	if ok, _ := a.Allow(ip, t0); ok {
		t.Fatal("query 3: want rate-limited")
	}
	// After 1s at 2/s → 2 new tokens.
	t1 := t0.Add(1 * time.Second)
	if ok, _ := a.Allow(ip, t1); !ok {
		t.Fatal("after 1s: want allowed")
	}
	if ok, _ := a.Allow(ip, t1); !ok {
		t.Fatal("after 1s (2nd): want allowed")
	}
	if ok, _ := a.Allow(ip, t1); ok {
		t.Fatal("after 1s (3rd): want rate-limited")
	}
}

func TestIPNotAllowed(t *testing.T) {
	a, _ := New([]string{"1.2.3.4"}, 100, 100, time.Minute)
	if ok, reason := a.Allow(net.ParseIP("9.9.9.9"), time.Now()); ok || reason != "ip-not-allowed" {
		t.Errorf("Allow(9.9.9.9) = (%v,%q); want (false, ip-not-allowed)", ok, reason)
	}
}

func TestSweep(t *testing.T) {
	a, _ := New([]string{"1.2.3.4"}, 100, 100, time.Minute)
	t0 := time.Unix(1000, 0)
	_, _ = a.Allow(net.ParseIP("1.2.3.4"), t0)
	if a.Len() != 1 {
		t.Fatalf("Len() = %d; want 1", a.Len())
	}
	// Sweep at t0+2min → bucket evicted.
	if n := a.Sweep(t0.Add(2 * time.Minute)); n != 1 {
		t.Errorf("Sweep() = %d; want 1", n)
	}
	if a.Len() != 0 {
		t.Errorf("after sweep Len() = %d; want 0", a.Len())
	}
}

func TestNewRejectsBadEntries(t *testing.T) {
	if _, err := New([]string{"not-an-ip"}, 10, 10, time.Minute); err == nil {
		t.Error("bad CIDR/IP: want error")
	}
	if _, err := New(nil, 0, 0, 0); err != nil {
		t.Errorf("empty allowed should still build (nftables is authoritative); got %v", err)
	}
}
