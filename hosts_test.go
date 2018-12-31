package gost

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

var hostsLookupTests = []struct {
	hosts []Host
	host  string
	ip    net.IP
}{
	{nil, "", nil},
	{nil, "example.com", nil},
	{[]Host{}, "", nil},
	{[]Host{}, "example.com", nil},
	{[]Host{NewHost(nil, "")}, "", nil},
	{[]Host{NewHost(nil, "example.com")}, "example.com", nil},
	{[]Host{NewHost(net.IPv4(192, 168, 1, 1), "")}, "", nil},
	{[]Host{NewHost(net.IPv4(192, 168, 1, 1), "example.com")}, "example.com", net.IPv4(192, 168, 1, 1)},
	{[]Host{NewHost(net.IPv4(192, 168, 1, 1), "example.com")}, "example", nil},
	{[]Host{NewHost(net.IPv4(192, 168, 1, 1), "example.com", "example", "examples")}, "example", net.IPv4(192, 168, 1, 1)},
	{[]Host{NewHost(net.IPv4(192, 168, 1, 1), "example.com", "example", "examples")}, "examples", net.IPv4(192, 168, 1, 1)},
}

func TestHostsLookup(t *testing.T) {
	for i, tc := range hostsLookupTests {
		hosts := NewHosts()
		hosts.AddHost(tc.hosts...)
		ip := hosts.Lookup(tc.host)
		if !ip.Equal(tc.ip) {
			t.Errorf("#%d test failed: lookup should be %s, got %s", i, tc.ip, ip)
		}
	}
}

var HostsReloadTests = []struct {
	r       io.Reader
	period  time.Duration
	host    string
	ip      net.IP
	stopped bool
}{
	{
		r:      nil,
		period: 0,
		host:   "",
		ip:     nil,
	},
	{
		r:      bytes.NewBufferString(""),
		period: 0,
		host:   "example.com",
		ip:     nil,
	},
	{
		r:      bytes.NewBufferString("reload 10s"),
		period: 10 * time.Second,
		host:   "example.com",
		ip:     nil,
	},
	{
		r:      bytes.NewBufferString("#reload 10s\ninvalid.ip.addr example.com"),
		period: 0,
		ip:     nil,
	},
	{
		r:      bytes.NewBufferString("reload 10s\n192.168.1.1"),
		period: 10 * time.Second,
		host:   "",
		ip:     nil,
	},
	{
		r:      bytes.NewBufferString("#reload 10s\n192.168.1.1 example.com"),
		period: 0,
		host:   "example.com",
		ip:     net.IPv4(192, 168, 1, 1),
	},
	{
		r:       bytes.NewBufferString("#reload 10s\n#192.168.1.1 example.com"),
		period:  0,
		host:    "example.com",
		ip:      nil,
		stopped: true,
	},
	{
		r:       bytes.NewBufferString("#reload 10s\n192.168.1.1 example.com example examples"),
		period:  0,
		host:    "example",
		ip:      net.IPv4(192, 168, 1, 1),
		stopped: true,
	},
	{
		r:       bytes.NewBufferString("#reload 10s\n192.168.1.1 example.com example examples"),
		period:  0,
		host:    "examples",
		ip:      net.IPv4(192, 168, 1, 1),
		stopped: true,
	},
}

func TestHostsReload(t *testing.T) {
	for i, tc := range HostsReloadTests {
		hosts := NewHosts()
		if err := hosts.Reload(tc.r); err != nil {
			t.Error(err)
		}
		if hosts.Period() != tc.period {
			t.Errorf("#%d test failed: period value should be %v, got %v",
				i, tc.period, hosts.Period())
		}
		ip := hosts.Lookup(tc.host)
		if !ip.Equal(tc.ip) {
			t.Errorf("#%d test failed: lookup should be %s, got %s", i, tc.ip, ip)
		}
		if tc.stopped {
			hosts.Stop()
			if hosts.Period() >= 0 {
				t.Errorf("period of the stopped reloader should be minus value")
			}
		}
		if hosts.Stopped() != tc.stopped {
			t.Errorf("#%d test failed: stopped value should be %v, got %v",
				i, tc.stopped, hosts.Stopped())
		}
	}
}
