// Package dnsx extracts the QNAME from a raw DNS query packet without
// resolving it. Used by the client's DNS interceptor to decide whether a
// query should be forwarded to an exit node (rule match) or answered by
// the local resolver.
package dnsx

import (
	"strings"

	"github.com/miekg/dns"
)

// QName returns the first question's QNAME from a raw DNS packet
// (lowercased, trailing dot stripped). Returns "" if the packet has no
// question or fails to parse — caller treats that as "no match → local".
func QName(msg []byte) string {
	var d dns.Msg
	if err := d.Unpack(msg); err != nil {
		return ""
	}
	if len(d.Question) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(d.Question[0].Name, "."))
}
