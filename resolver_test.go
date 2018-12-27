package gost

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"time"
)

var dnsTests = []struct {
	ns   NameServer
	host string
	pass bool
}{
	{NameServer{Addr: "1.1.1.1"}, "github.com", true},
	{NameServer{Addr: "1.1.1.1:53"}, "github.com", true},
	{NameServer{Addr: "1.1.1.1:53", Protocol: "tcp"}, "github.com", true},
	{NameServer{Addr: "1.1.1.1:853", Protocol: "tls"}, "github.com", true},
	{NameServer{Addr: "1.1.1.1:853", Protocol: "tls", Hostname: "example.com"}, "github.com", false},
	{NameServer{Addr: "1.1.1.1:853", Protocol: "tls", Hostname: "cloudflare-dns.com"}, "github.com", true},
	{NameServer{Addr: "https://cloudflare-dns.com/dns-query", Protocol: "https"}, "github.com", true},
	{NameServer{Addr: "https://1.0.0.1/dns-query", Protocol: "https"}, "github.com", true},
	{NameServer{Addr: "1.1.1.1:12345", Timeout: 1 * time.Second}, "github.com", false},
	{NameServer{Addr: "1.1.1.1:12345", Protocol: "tcp", Timeout: 1 * time.Second}, "github.com", false},
	{NameServer{Addr: "1.1.1.1:12345", Protocol: "tls", Timeout: 1 * time.Second}, "github.com", false},
	{NameServer{Addr: "https://1.0.0.1:12345/dns-query", Protocol: "https", Timeout: 1 * time.Second}, "github.com", false},
}

func dnsResolverRoundtrip(t *testing.T, r Resolver, host string) error {
	ips, err := r.Resolve(host)
	t.Log(host, ips, err)
	if err != nil {
		return err
	}

	return nil
}

func TestDNSResolver(t *testing.T) {
	for i, tc := range dnsTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			ns := tc.ns
			if err := ns.Init(); err != nil {
				t.Error(err)
			}
			t.Log(ns)
			r := NewResolver(0, 0, ns)
			err := dnsResolverRoundtrip(t, r, tc.host)
			if err != nil {
				if tc.pass {
					t.Error("got error:", err)
				}
			} else {
				if !tc.pass {
					t.Error("should failed")
				}
			}
		})
	}
}

var resolverReloadTests = []struct {
	r io.Reader

	timeout time.Duration
	ttl     time.Duration
	domain  string
	period  time.Duration
	ns      *NameServer

	stopped bool
}{
	{
		r: nil,
	},
	{
		r: bytes.NewBufferString(""),
	},
	{
		r:      bytes.NewBufferString("reload 10s"),
		period: 10 * time.Second,
	},
	{
		r:       bytes.NewBufferString("timeout 10s\nreload 10s\n"),
		timeout: 10 * time.Second,
		period:  10 * time.Second,
	},
	{
		r:       bytes.NewBufferString("ttl 10s\ntimeout 10s\nreload 10s\n"),
		timeout: 10 * time.Second,
		period:  10 * time.Second,
		ttl:     10 * time.Second,
	},
	{
		r:       bytes.NewBufferString("domain example.com\nttl 10s\ntimeout 10s\nreload 10s\n"),
		timeout: 10 * time.Second,
		period:  10 * time.Second,
		ttl:     10 * time.Second,
		domain:  "example.com",
	},
	{
		r: bytes.NewBufferString("1.1.1.1"),
		ns: &NameServer{
			Addr:    "1.1.1.1",
			Timeout: DefaultResolverTimeout,
		},
		stopped: true,
	},
	{
		r: bytes.NewBufferString("timeout 10s\nsearch\nnameserver  \nnameserver 1.1.1.1 udp"),
		ns: &NameServer{
			Protocol: "udp",
			Addr:     "1.1.1.1",
			Timeout:  10 * time.Second,
		},
		timeout: 10 * time.Second,
		stopped: true,
	},
	{
		r: bytes.NewBufferString("1.1.1.1 tcp"),
		ns: &NameServer{
			Addr:     "1.1.1.1",
			Protocol: "tcp",
			Timeout:  DefaultResolverTimeout,
		},
		stopped: true,
	},
	{
		r: bytes.NewBufferString("1.1.1.1:853 tls cloudflare-dns.com"),
		ns: &NameServer{
			Addr:     "1.1.1.1:853",
			Protocol: "tls",
			Hostname: "cloudflare-dns.com",
			Timeout:  DefaultResolverTimeout,
		},
		stopped: true,
	},
	{
		r: bytes.NewBufferString("1.1.1.1:853 tls"),
		ns: &NameServer{
			Addr:     "1.1.1.1:853",
			Protocol: "tls",
			Timeout:  DefaultResolverTimeout,
		},
		stopped: true,
	},
	{
		r:       bytes.NewBufferString("1.0.0.1:53 https"),
		stopped: true,
	},
	{
		r: bytes.NewBufferString("https://1.0.0.1/dns-query https"),
		ns: &NameServer{
			Addr:     "https://1.0.0.1/dns-query",
			Protocol: "https",
			Timeout:  DefaultResolverTimeout,
		},
		stopped: true,
	},
}

func TestResolverReload(t *testing.T) {
	for i, tc := range resolverReloadTests {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			r := newResolver(0, 0)
			if err := r.Reload(tc.r); err != nil {
				t.Error(err)
			}
			t.Log(r.String())
			if r.Timeout != tc.timeout {
				t.Errorf("timeout value should be %v, got %v",
					tc.timeout, r.Timeout)
			}
			if r.TTL != tc.ttl {
				t.Errorf("ttl value should be %v, got %v",
					tc.ttl, r.TTL)
			}
			if r.Period() != tc.period {
				t.Errorf("period value should be %v, got %v",
					tc.period, r.period)
			}
			if r.domain != tc.domain {
				t.Errorf("domain value should be %v, got %v",
					tc.domain, r.domain)
			}

			var ns *NameServer
			if len(r.Servers) > 0 {
				ns = &r.Servers[0]
			}

			if !compareNameServer(ns, tc.ns) {
				t.Errorf("nameserver not equal, should be %v, got %v",
					tc.ns, r.Servers)
			}

			if tc.stopped {
				r.Stop()
			}
			if r.Stopped() != tc.stopped {
				t.Errorf("stopped value should be %v, got %v",
					tc.stopped, r.Stopped())
			}
		})
	}
}

func compareNameServer(n1, n2 *NameServer) bool {
	if n1 == n2 {
		return true
	}
	if n1 == nil || n2 == nil {
		return false
	}
	return n1.Addr == n2.Addr &&
		n1.Hostname == n2.Hostname &&
		n1.Protocol == n2.Protocol &&
		n1.Timeout == n2.Timeout
}
