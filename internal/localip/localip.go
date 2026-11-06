// Package localip discovers the host's own IP addresses so rdns-client can
// exclude them from the nftables redirects (traffic to the node's own
// endpoints — the autoscript VPN listeners — must NOT be hijacked).
//
// Why auto-detect (and not just a static config list):
//
//   - Residential / dynamic-IP hosts change address (DHCP lease, reconnect,
//     CGNAT re-pool). A hardcoded local_ips goes stale and either breaks the
//     VPN (stale entry no longer matches, so the node's own 443 gets
//     redirected) or leaks interception (stale entry over-matches).
//   - On a NAT'd residential host, inbound VPN traffic is DNAT'd by the
//     router, so it arrives at the box with daddr = the box's LOCAL
//     interface address — which is exactly what we enumerate here. The
//     public IP never appears as a packet destination on the host, so
//     matching on interface IPs is both correct and stable across public-IP
//     churn.
//
// The detection is best-effort and re-runnable: rdns-client refreshes the
// ruleset on a timer (see cmd/rdns-client) so a mid-run address change is
// picked up without a restart.
package localip

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Options tunes discovery.
type Options struct {
	// Include, when non-empty, restricts to interfaces whose name matches
	// one of these prefixes (e.g. {"eth", "en", "wlan"}). Empty = all
	// eligible interfaces.
	Include []string
	// Exclude drops interfaces whose name matches one of these prefixes
	// (e.g. {"docker", "br-", "veth", "tun", "tap"}). Applied after Include.
	Exclude []string
	// Extra are manually-configured addresses merged with the discovered
	// set (deduped). Lets an operator pin an address auto-detect misses.
	Extra []net.IP
}

// Detect returns the host's own unicast addresses (IPv4 + IPv6), sorted and
// deduped. Loopback and down interfaces are skipped.
func Detect(opts Options) ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("localip: list interfaces: %w", err)
	}
	seen := make(map[string]bool)
	var out []net.IP

	add := func(ip net.IP) {
		if ip == nil {
			return
		}
		s := ip.String()
		if v4 := ip.To4(); v4 != nil {
			s = v4.String()
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, ip)
		}
	}

	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if !nameAllowed(ifc.Name, opts.Include, opts.Exclude) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			// One interface failing shouldn't abort discovery; skip it.
			continue
		}
		for _, a := range addrs {
			var ipnet *net.IPNet
			switch v := a.(type) {
			case *net.IPNet:
				ipnet = v
			case *net.IPAddr:
				ipnet = &net.IPNet{IP: v.IP, Mask: v.IP.DefaultMask()}
			}
			if ipnet == nil {
				continue
			}
			add(ipnet.IP)
		}
	}

	for _, ip := range opts.Extra {
		add(ip)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out, nil
}

// nameAllowed applies the Include-then-Exclude prefix rules.
func nameAllowed(name string, include, exclude []string) bool {
	if len(include) > 0 && !hasPrefixAny(name, include) {
		return false
	}
	if hasPrefixAny(name, exclude) {
		return false
	}
	return true
}

func hasPrefixAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if p != "" && strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// DefaultExclude lists interface prefixes that are never the node's WAN
// address (containers, tunnels, bridges). tun/tap are excluded because
// OpenVPN's tun0 address is not an inbound-VPN endpoint we must protect —
// and intercepting TUN-routed traffic is handled by the PREROUTING chain,
// not by a daddr match.
var DefaultExclude = []string{"docker", "br-", "veth", "virbr", "lo", "tun", "tap", "wg"}
