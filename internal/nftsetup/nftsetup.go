// Package nftsetup generates and applies the client-side nftables rules
// that hand intercepted traffic to the rdns interceptors (PRD §5, §11).
//
// # Why three hooks (and not just PREROUTING as in the PRD draft)
//
// On a VPN node (autoscript) the end-user traffic is RE-ORIGINATED by local
// processes: dropbear/ssh-ws and xray dial outbound on behalf of SSH-WS and
// VLESS/Trojan clients, and OpenVPN packets enter from a TUN interface. So:
//
//   - SSH-WS / VLESS / Trojan user traffic → locally generated → OUTPUT (TCP 80/443 only)
//   - OpenVPN (TUN) user traffic → received from tun0 → PREROUTING (DNS 53 + TCP 80/443)
//
// We do NOT redirect UDP 53 in the OUTPUT chain. Local proxy daemons dial TCP
// to egress targets; glibc and host resolvers (dnf, curl, systemd) send local
// UDP queries from the host itself. Redirecting local UDP 53 would break local
// host resolution due to Netfilter NAT reply mismatches and dead listeners on stop.
//
// # Why a conntrack-mark INPUT chain
//
// After a redirect the packet's destination becomes local, so it is
// re-delivered through the INPUT chain — where a strict firewall (autoscript
// runs firewalld with an allowlist of just 22/3303/109/80/443/7300/1194)
// would drop it, because the interceptor ports (5353/14300) are NOT
// allowlisted (and must not be: opening them publicly would expose the
// interceptors to the internet). Each redirect therefore stamps a
// conntrack mark, and an INPUT chain at priority -150 (before firewalld's
// filter chain) accepts exactly that mark.
//
// # Exclusions that keep the node itself working
//
//  1. `socket mark <SO_MARK> accept` — rdns-client stamps its own outbound
//     sockets (tunnel, DNS forward, direct dials) so they are never
//     redirected back into the interceptors (loop prevention).
//  2. `oifname "lo" accept` — all loopback traffic (nginx 81/444, xray API
//     10085, ssh-ws 8888, WebAPI 9000, systemd-resolved 127.0.0.53, ...).
//  3. `ip daddr {<local IPs>} accept` — the node's own endpoints: inbound
//     VPN endpoints (VLESS/Trojan on 443 via HAProxy, SSH 22/109/3303,
//     OpenVPN 1194) and local health checks to the node's own IP.
//
// The generator is pure (returns the nft script text) so it is unit-
// tested; the applier shells out to `nft` and is Linux-only.
package nftsetup

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// CTMark is stamped on redirected packets so the INPUT chain can let them
// reach the local interceptors before the strict firewall sees them.
const CTMark = 0x00d1920d

// Config describes the ruleset to generate.
type Config struct {
	// Table is the nftables table name (default "rdns"). firewalld uses its
	// own tables, so a dedicated table coexists cleanly.
	Table string
	// Priority for all three chains (default -150, i.e. the "mangle-like"
	// range, before firewalld's filter chain at 0).
	Priority int
	// Mark is the SO_MARK to skip (rdns-client's own egress).
	Mark uint32
	// LocalIPs are the node's own addresses — traffic to these is NOT
	// redirected (protects the autoscript VPN endpoints).
	LocalIPs []net.IP
	// DNSTarget is the local DNS interceptor port (default 5353).
	DNSTarget int
	// SNITarget is the local SNI interceptor port (default 14300).
	SNITarget int
	// QUICTarget is the local QUIC/UDP interceptor port (default 14400).
	QUICTarget int
}

func (c *Config) defaults() {
	if c.Table == "" {
		c.Table = "rdns"
	}
	if c.Priority == 0 {
		c.Priority = -150
	}
	if c.DNSTarget == 0 {
		c.DNSTarget = 5353
	}
	if c.SNITarget == 0 {
		c.SNITarget = 14300
	}
	if c.QUICTarget == 0 {
		c.QUICTarget = 14400
	}
}

// ipSet renders the LocalIPs for the given family (nil = both). Returns ""
// when there are no addresses of that family.
func (c *Config) ipSet(family string) string {
	var out []string
	seen := make(map[string]bool)
	for _, ip := range c.LocalIPs {
		var s string
		switch family {
		case "v4":
			if ip.To4() == nil {
				continue
			}
			s = ip.To4().String()
		case "v6":
			if ip.To4() != nil {
				continue
			}
			s = ip.String()
		default:
			s = ip.String()
			if v4 := ip.To4(); v4 != nil {
				s = v4.String()
			}
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		return ""
	}
	return " { " + strings.Join(out, ", ") + " }"
}

// preroutingRedirects renders the daddr exclusion + both DNS and SNI redirects
// for traffic arriving on external / TUN interfaces (e.g. OpenVPN clients).
func (c *Config) preroutingRedirects(family string) string {
	var b strings.Builder
	fam := "v4"
	if family == "ip6" {
		fam = "v6"
	}
	if set := c.ipSet(fam); set != "" {
		fmt.Fprintf(&b, "\t\t%s daddr%s accept\n", family, set)
	}
	fmt.Fprintf(&b, "\t\tudp dport 53 ct mark set %#x redirect to :%d\n", CTMark, c.DNSTarget)
	fmt.Fprintf(&b, "\t\ttcp dport { 80, 443 } ct mark set %#x redirect to :%d\n", CTMark, c.SNITarget)
	return b.String()
}

// tproxyRules renders the TPROXY rule for incoming external / TUN UDP 443 traffic.
func (c *Config) tproxyRules(family string) string {
	var b strings.Builder
	fam := "v4"
	if family == "ip6" {
		fam = "v6"
	}
	if set := c.ipSet(fam); set != "" {
		fmt.Fprintf(&b, "\t\t%s daddr%s accept\n", family, set)
	}
	fmt.Fprintf(&b, "\t\tudp dport 443 meta mark set %#x tproxy to :%d accept\n", CTMark, c.QUICTarget)
	return b.String()
}

// outputRedirects renders the daddr exclusion + SNI redirects (TCP 80, 443) for
// locally-generated proxy traffic (SSH-WS, Xray, Trojan). UDP 53 and UDP 443 are
// deliberately omitted from the output chain: UDP NAT redirect rewrites daddr to
// localhost and destroys the original destination IP (UDP lacks conntrack SO_ORIGINAL_DST).
// UDP 443 (QUIC) is cleanly intercepted via TPROXY in tproxy_prerouting.
func (c *Config) outputRedirects(family string) string {
	var b strings.Builder
	fam := "v4"
	if family == "ip6" {
		fam = "v6"
	}
	if set := c.ipSet(fam); set != "" {
		fmt.Fprintf(&b, "\t\t%s daddr%s accept\n", family, set)
	}
	fmt.Fprintf(&b, "\t\ttcp dport { 80, 443 } ct mark set %#x redirect to :%d\n", CTMark, c.SNITarget)
	return b.String()
}

// Render returns the full nftables script (IPv4 + IPv6 tables). It is
// idempotent: it flushes and recreates only this project's tables, so
// re-running (install + upgrade) never touches firewalld's tables.
func (c *Config) Render() string {
	c.defaults()
	var b strings.Builder
	fmt.Fprintf(&b, "# generated by rdns nftsetup — do not edit\n")
	for _, family := range []string{"ip", "ip6"} {
		// "add table" is idempotent (no error if it already exists), unlike
		// "flush table" which errors with ENOENT on a table that was never
		// created (fresh install / first run after boot). Creating it first
		// guarantees the following flush always has something to flush.
		fmt.Fprintf(&b, "add table %s %s\n", family, c.Table)
		fmt.Fprintf(&b, "flush table %s %s\n", family, c.Table)
		fmt.Fprintf(&b, "table %s %s {\n", family, c.Table)

		// OUTPUT: locally-generated user traffic (SSH-WS/VLESS/Trojan).
		fmt.Fprintf(&b, "\tchain output {\n")
		fmt.Fprintf(&b, "\t\ttype nat hook output priority -100; policy accept;\n")
		fmt.Fprintf(&b, "\t\tsocket mark %#x accept\n", c.Mark)
		fmt.Fprintf(&b, "\t\toifname \"lo\" accept\n")
		b.WriteString(c.outputRedirects(family))
		b.WriteString("\t}\n")

		// PREROUTING: TUN-routed user traffic (OpenVPN).
		fmt.Fprintf(&b, "\tchain prerouting {\n")
		fmt.Fprintf(&b, "\t\ttype nat hook prerouting priority -100; policy accept;\n")
		b.WriteString(c.preroutingRedirects(family))
		b.WriteString("\t}\n")

		// TPROXY PREROUTING: TUN-routed UDP 443 (QUIC/HTTP3) traffic.
		fmt.Fprintf(&b, "\tchain tproxy_prerouting {\n")
		fmt.Fprintf(&b, "\t\ttype filter hook prerouting priority -150; policy accept;\n")
		fmt.Fprintf(&b, "\t\tsocket mark %#x accept\n", c.Mark)
		fmt.Fprintf(&b, "\t\toifname \"lo\" accept\n")
		b.WriteString(c.tproxyRules(family))
		b.WriteString("\t}\n")

		// INPUT: let only our redirected packets past the strict firewall.
		fmt.Fprintf(&b, "\tchain input {\n")
		fmt.Fprintf(&b, "\t\ttype filter hook input priority %d; policy accept;\n", c.Priority)
		fmt.Fprintf(&b, "\t\tct mark %#x accept\n", CTMark)
		fmt.Fprintf(&b, "\t\tmeta mark %#x accept\n", CTMark)
		b.WriteString("\t}\n")

		b.WriteString("}\n")
	}
	return b.String()
}

// UninstallScript returns the nft script that removes the tables. It is
// safe to run even if the tables were never created (e.g. Apply failed
// before Unapply is called during rollback/stop): "add table" makes the
// following flush+delete always have a valid target instead of erroring
// with ENOENT on a table that doesn't exist.
func (c *Config) UninstallScript() string {
	c.defaults()
	return fmt.Sprintf(
		"add table ip %s\nflush table ip %s\ndelete table ip %s\nadd table ip6 %s\nflush table ip6 %s\ndelete table ip6 %s\n",
		c.Table, c.Table, c.Table, c.Table, c.Table, c.Table)
}
