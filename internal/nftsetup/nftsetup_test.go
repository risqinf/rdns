package nftsetup

import (
	"net"
	"strings"
	"testing"
)

func TestRenderIPv4(t *testing.T) {
	c := &Config{
		Mark:     0xd1920d7,
		LocalIPs: []net.IP{net.ParseIP("203.0.113.10")},
	}
	got := c.Render()

	wantFragments := []string{
		"flush table ip rdns",
		"table ip rdns {",
		"chain output {",
		"type nat hook output priority -100; policy accept;",
		"socket mark 0xd1920d7 accept",
		`oifname "lo" accept`,
		"ip daddr { 203.0.113.10 } accept",
		"udp dport 53 ct mark set 0xd1920d redirect to :5353",
		"tcp dport { 80, 443 } ct mark set 0xd1920d redirect to :14300",
		"udp dport 443 meta mark set 0xd1920d tproxy to :14400 accept",
		"chain prerouting {",
		"chain tproxy_prerouting {",
		"chain input {",
		"ct mark 0xd1920d accept",
		"meta mark 0xd1920d accept",
	}
	for _, w := range wantFragments {
		if !strings.Contains(got, w) {
			t.Errorf("Render() missing %q\n----\n%s", w, got)
		}
	}
	// The output chain must NOT redirect UDP 53 (preserves host DNS)
	// and daddr exclusion must come BEFORE the TCP redirect.
	outChain := got[strings.Index(got, "chain output"):strings.Index(got, "chain prerouting")]
	if strings.Contains(outChain, "udp dport 53") {
		t.Errorf("output chain must not redirect udp 53 (preserves host DNS)\n%s", outChain)
	}
	if strings.Index(outChain, "daddr") > strings.Index(outChain, "tcp dport") {
		t.Errorf("daddr exclusion must precede redirects in the output chain\n%s", outChain)
	}
}

func TestRenderIPv6(t *testing.T) {
	c := &Config{Mark: 1, LocalIPs: []net.IP{net.ParseIP("2001:db8::1")}}
	got := c.Render()
	for _, w := range []string{
		"flush table ip6 rdns",
		"table ip6 rdns {",
		"ip6 daddr { 2001:db8::1 } accept",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("Render() missing %q\n----\n%s", w, got)
		}
	}
}

func TestRenderCustomTargets(t *testing.T) {
	c := &Config{
		Priority:  10,
		Mark:      1,
		LocalIPs:  []net.IP{net.ParseIP("192.168.1.5"), net.ParseIP("192.168.1.6")},
		DNSTarget:  15353,
		SNITarget:  24300,
		QUICTarget: 24400,
	}
	got := c.Render()
	for _, w := range []string{
		"priority 10;",
		"socket mark 0x1 accept",
		"{ 192.168.1.5, 192.168.1.6 }",
		"redirect to :15353",
		"redirect to :24300",
		"tproxy to :24400",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("Render() missing %q\n----\n%s", w, got)
		}
	}
}

func TestRenderNoLocalIPs(t *testing.T) {
	c := &Config{Mark: 1}
	got := c.Render()
	if strings.Contains(got, "daddr") {
		t.Errorf("no LocalIPs: should not emit a daddr line\n%s", got)
	}
}

func TestMixedFamilies(t *testing.T) {
	c := &Config{Mark: 1, LocalIPs: []net.IP{net.ParseIP("192.168.1.5"), net.ParseIP("2001:db8::1")}}
	got := c.Render()
	// IPv4 table gets the v4 IP, IPv6 table gets the v6 IP.
	ipTable := got[strings.Index(got, "table ip "):strings.Index(got, "table ip6 ")]
	if !strings.Contains(ipTable, "192.168.1.5") || strings.Contains(ipTable, "2001:db8::1") {
		t.Errorf("ip table should contain only the v4 IP\n%s", ipTable)
	}
	ip6Table := got[strings.Index(got, "table ip6 "):]
	if !strings.Contains(ip6Table, "2001:db8::1") || strings.Contains(ip6Table, "192.168.1.5") {
		t.Errorf("ip6 table should contain only the v6 IP\n%s", ip6Table)
	}
}

func TestUninstallScript(t *testing.T) {
	c := &Config{}
	got := c.UninstallScript()
	if !strings.Contains(got, "delete table ip rdns") || !strings.Contains(got, "delete table ip6 rdns") {
		t.Errorf("UninstallScript missing delete: %s", got)
	}
	if !strings.Contains(got, "add table ip rdns") || !strings.Contains(got, "add table ip6 rdns") {
		t.Errorf("UninstallScript missing add (needed so a never-created table doesn't error): %s", got)
	}
}

// Regression test for a first-boot bug: `nft -f` errors with "No such file
// or directory" on `flush table ip rdns` when the table was never created
// (fresh install, or after a reboot wiped the ruleset). `add table` right
// before each `flush table` must always come first, for both families, in
// both Render() and UninstallScript().
func TestFlushIsAlwaysPrecededByAddTable(t *testing.T) {
	check := func(t *testing.T, script string) {
		t.Helper()
		for _, family := range []string{"ip", "ip6"} {
			addLine := "add table " + family + " rdns"
			flushLine := "flush table " + family + " rdns"
			addIdx := strings.Index(script, addLine)
			flushIdx := strings.Index(script, flushLine)
			if addIdx == -1 {
				t.Errorf("missing %q\n----\n%s", addLine, script)
				continue
			}
			if flushIdx == -1 {
				t.Errorf("missing %q\n----\n%s", flushLine, script)
				continue
			}
			if addIdx > flushIdx {
				t.Errorf("%q must precede %q so flush never targets a nonexistent table\n----\n%s", addLine, flushLine, script)
			}
		}
	}
	c := &Config{Mark: 1, LocalIPs: []net.IP{net.ParseIP("203.0.113.10")}}
	t.Run("Render", func(t *testing.T) { check(t, c.Render()) })
	t.Run("UninstallScript", func(t *testing.T) { check(t, c.UninstallScript()) })
}
