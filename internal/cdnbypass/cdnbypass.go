// Package cdnbypass identifies heavy media streaming and file download CDNs.
// In SmartDNS split-routing mode, DNS for these domains is resolved via the
// exit node for geo-accuracy, while TCP/QUIC media streams connect directly,
// preserving >99% of exit node tunnel bandwidth.
package cdnbypass

import "strings"

// DefaultMediaCDNs lists domain suffixes responsible for bulk media/video chunks.
var DefaultMediaCDNs = []string{
	"nflxvideo.net",
	"nflxso.net",
	"googlevideo.com",
	"tiktokcdn.com",
	"byteoversea.com",
	"ibytedtos.com",
	"steamcontent.com",
	"bilivideo.com",
	"hotstar-cdn.net",
	"akamaized.net",
	"akamaihd.net",
	"wetvinfo.com",
	"aiv-cdn.net",
}

// IsMediaCDN reports whether a domain is a known bulk video/media delivery CDN.
func IsMediaCDN(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, cdn := range DefaultMediaCDNs {
		if h == cdn || strings.HasSuffix(h, "."+cdn) {
			return true
		}
	}
	return false
}
