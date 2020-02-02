package gost

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

var dnsTests = []struct {
	ns   NameServer
	host string
	pass bool
}{
	{NameServer{Addr: "1.1.1.1"}, "192.168.1.1", true},
	{NameServer{Addr: "1.1.1.1"}, "github", true},
	{NameServer{Addr: "1.1.1.1"}, "github.com", true},
	{NameServer{Addr: "1.1.1.1:53"}, "github.com", true},
	{NameServer{Addr: "1.1.1.1:53", Protocol: "tcp"}, "github.com", true},
	{NameServer{Addr: "1.1.1.1:853", Protocol: "tls"}, "github.com", true},
	{NameServer{Addr: "1.1.1.1:853", Protocol: "tls", Hostname: "example.com"}, "github.com", false},
	{NameServer{Addr: "1.1.1.1:853", Protocol: "tls", Hostname: "cloudflare-dns.com"}, "github.com", true},
	{NameServer{Addr: "https://cloudflare-dns.com/dns-query", Protocol: "https"}, "github.com", true},
	{NameServer{Addr: "https://1.0.0.1/dns-query", Protocol: "https"}, "github.com", true},
	{NameServer{Addr: "1.1.1.1:12345"}, "github.com", false},
	{NameServer{Addr: "1.1.1.1:12345", Protocol: "tcp"}, "github.com", false},
	{NameServer{Addr: "1.1.1.1:12345", Protocol: "tls"}, "github.com", false},
	{NameServer{Addr: "https://1.0.0.1:12345/dns-query", Protocol: "https"}, "github.com", false},
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
			t.Log(ns)
			r := NewResolver(0, ns)
			resolv := r.(*resolver)
			resolv.domain = "com"
			if err := r.Init(); err != nil {
				t.Error("got error:", err)
			}
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

var resolverCacheTests = []struct {
	name   string
	ips    []net.IP
	ttl    time.Duration
	result []net.IP
}{
	{"", nil, 0, nil},
	{"", []net.IP{net.IPv4(192, 168, 1, 1)}, 0, nil},
	{"", []net.IP{net.IPv4(192, 168, 1, 1)}, 10 * time.Second, nil},
	{"example.com", nil, 10 * time.Second, nil},
	{"example.com", []net.IP{}, 10 * time.Second, nil},
	{"example.com", []net.IP{net.IPv4(192, 168, 1, 1)}, 0, nil},
	{"example.com", []net.IP{net.IPv4(192, 168, 1, 1)}, -1, nil},
	{"example.com", []net.IP{net.IPv4(192, 168, 1, 1)}, 10 * time.Second,
		[]net.IP{net.IPv4(192, 168, 1, 1)}},
	{"example.com", []net.IP{net.IPv4(192, 168, 1, 1), net.IPv4(192, 168, 1, 2)}, 10 * time.Second,
		[]net.IP{net.IPv4(192, 168, 1, 1), net.IPv4(192, 168, 1, 2)}},
}

/*
func TestResolverCache(t *testing.T) {
	isEqual := func(a, b []net.IP) bool {
		if a == nil && b == nil {
			return true
		}

		if a == nil || b == nil || len(a) != len(b) {
			return false
		}

		for i := range a {
			if !a[i].Equal(b[i]) {
				return false
			}
		}
		return true
	}
	for i, tc := range resolverCacheTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			r := newResolver(tc.ttl)
			r.cache.storeCache(tc.name, tc.ips, tc.ttl)
			ips := r.cache.loadCache(tc.name, tc.ttl)

			if !isEqual(tc.result, ips) {
				t.Error("unexpected cache value:", tc.name, ips, tc.ttl)
			}
		})
	}
}
*/

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
			Addr: "1.1.1.1",
		},
		stopped: true,
	},
	{
		r: bytes.NewBufferString("\n# comment\ntimeout 10s\nsearch\nnameserver  \nnameserver 1.1.1.1 udp"),
		ns: &NameServer{
			Protocol: "udp",
			Addr:     "1.1.1.1",
		},
		timeout: 10 * time.Second,
		stopped: true,
	},
	{
		r: bytes.NewBufferString("1.1.1.1 tcp"),
		ns: &NameServer{
			Addr:     "1.1.1.1",
			Protocol: "tcp",
		},
		stopped: true,
	},
	{
		r: bytes.NewBufferString("1.1.1.1:853 tls cloudflare-dns.com"),
		ns: &NameServer{
			Addr:     "1.1.1.1:853",
			Protocol: "tls",
			Hostname: "cloudflare-dns.com",
		},
		stopped: true,
	},
	{
		r: bytes.NewBufferString("1.1.1.1:853 tls"),
		ns: &NameServer{
			Addr:     "1.1.1.1:853",
			Protocol: "tls",
		},
		stopped: true,
	},
	{
		r:       bytes.NewBufferString("1.0.0.1:53 https"),
		stopped: true,
	},
	{
		r: bytes.NewBufferString("https://1.0.0.1/dns-query"),
		ns: &NameServer{
			Addr:     "https://1.0.0.1/dns-query",
			Protocol: "https",
		},
		stopped: true,
	},
}

func TestResolverReload(t *testing.T) {
	for i, tc := range resolverReloadTests {
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			r := newResolver(0)
			if err := r.Reload(tc.r); err != nil {
				t.Error(err)
			}
			t.Log(r.String())
			if r.TTL() != tc.ttl {
				t.Errorf("ttl value should be %v, got %v",
					tc.ttl, r.TTL())
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
			if len(r.servers) > 0 {
				ns = &r.servers[0]
			}

			if !compareNameServer(ns, tc.ns) {
				t.Errorf("nameserver not equal, should be %v, got %v",
					tc.ns, r.servers)
			}

			if tc.stopped {
				r.Stop()
				if r.Period() >= 0 {
					t.Errorf("period of the stopped reloader should be minus value")
				}
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
		n1.Protocol == n2.Protocol
}
