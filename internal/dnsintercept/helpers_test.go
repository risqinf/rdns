package dnsintercept

import (
	"context"
	"net"
	"time"

	"github.com/miekg/dns"
)

// dnsMsg aliases *dns.Msg to keep the fake-DNS code terse.
type dnsMsg = dns.Msg

// newReply builds a minimal NOERROR reply echoing the query.
func newReply(req dnsMsg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(&req)
	if len(req.Question) > 0 {
		q := req.Question[0]
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: q.Qclass, Ttl: 30},
			A:   net.ParseIP("203.0.113.99"),
		})
	}
	return resp
}

// query builds a DNS A query for name.
func query(name string) *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	return m
}

// dnsClient is a thin wrapper over *dns.Client for the tests.
type dnsClient struct{ *dns.Client }

func newClient() *dnsClient { return &dnsClient{&dns.Client{Timeout: 2 * time.Second}} }

// send sends a query and returns the response (nil if none within timeout).
func (c *dnsClient) send(ctx context.Context, m *dns.Msg, addr string) (*dns.Msg, error) {
	resp, _, err := c.Client.ExchangeContext(ctx, m, addr)
	return resp, err
}
