package gost

import (
	"bytes"
	"fmt"
	"io"
	"testing"
	"time"
)

var bypassContainTests = []struct {
	patterns []string
	reversed bool
	addr     string
	bypassed bool
}{
	// empty pattern
	{[]string{""}, false, "", false},
	{[]string{""}, false, "192.168.1.1", false},
	{[]string{""}, true, "", false},
	{[]string{""}, true, "192.168.1.1", false},

	// IP address
	{[]string{"192.168.1.1"}, false, "192.168.1.1", true},
	{[]string{"192.168.1.1"}, true, "192.168.1.1", false},
	{[]string{"192.168.1.1"}, false, "192.168.1.2", false},
	{[]string{"192.168.1.1"}, true, "192.168.1.2", true},
	{[]string{"0.0.0.0"}, false, "0.0.0.0", true},
	{[]string{"0.0.0.0"}, true, "0.0.0.0", false},

	// CIDR address
	{[]string{"192.168.1.0/0"}, false, "1.2.3.4", true},
	{[]string{"192.168.1.0/0"}, true, "1.2.3.4", false},
	{[]string{"192.168.1.0/8"}, false, "192.1.0.255", true},
	{[]string{"192.168.1.0/8"}, true, "192.1.0.255", false},
	{[]string{"192.168.1.0/8"}, false, "191.1.0.255", false},
	{[]string{"192.168.1.0/8"}, true, "191.1.0.255", true},
	{[]string{"192.168.1.0/16"}, false, "192.168.0.255", true},
	{[]string{"192.168.1.0/16"}, true, "192.168.0.255", false},
	{[]string{"192.168.1.0/16"}, false, "192.0.1.255", false},
	{[]string{"192.168.1.0/16"}, true, "192.0.0.255", true},
	{[]string{"192.168.1.0/24"}, false, "192.168.1.255", true},
	{[]string{"192.168.1.0/24"}, true, "192.168.1.255", false},
	{[]string{"192.168.1.0/24"}, false, "192.168.0.255", false},
	{[]string{"192.168.1.0/24"}, true, "192.168.0.255", true},
	{[]string{"192.168.1.1/32"}, false, "192.168.1.1", true},
	{[]string{"192.168.1.1/32"}, true, "192.168.1.1", false},
	{[]string{"192.168.1.1/32"}, false, "192.168.1.2", false},
	{[]string{"192.168.1.1/32"}, true, "192.168.1.2", true},

	// plain domain
	{[]string{"www.example.com"}, false, "www.example.com", true},
	{[]string{"www.example.com"}, true, "www.example.com", false},
	{[]string{"http://www.example.com"}, false, "http://www.example.com", true},
	{[]string{"http://www.example.com"}, true, "http://www.example.com", false},
	{[]string{"http://www.example.com"}, false, "http://example.com", false},
	{[]string{"http://www.example.com"}, true, "http://example.com", true},
	{[]string{"www.example.com"}, false, "example.com", false},
	{[]string{"www.example.com"}, true, "example.com", true},

	// host:port
	{[]string{"192.168.1.1"}, false, "192.168.1.1:80", true},
	{[]string{"192.168.1.1"}, true, "192.168.1.1:80", false},
	{[]string{"192.168.1.1:80"}, false, "192.168.1.1", false},
	{[]string{"192.168.1.1:80"}, true, "192.168.1.1", true},
	{[]string{"192.168.1.1:80"}, false, "192.168.1.1:80", false},
	{[]string{"192.168.1.1:80"}, true, "192.168.1.1:80", true},
	{[]string{"192.168.1.1:80"}, false, "192.168.1.1:8080", false},
	{[]string{"192.168.1.1:80"}, true, "192.168.1.1:8080", true},

	{[]string{"example.com"}, false, "example.com:80", true},
	{[]string{"example.com"}, true, "example.com:80", false},
	{[]string{"example.com:80"}, false, "example.com", false},
	{[]string{"example.com:80"}, true, "example.com", true},
	{[]string{"example.com:80"}, false, "example.com:80", false},
	{[]string{"example.com:80"}, true, "example.com:80", true},
	{[]string{"example.com:80"}, false, "example.com:8080", false},
	{[]string{"example.com:80"}, true, "example.com:8080", true},

	// domain wildcard

	{[]string{"*"}, false, "", false},
	{[]string{"*"}, false, "192.168.1.1", true},
	{[]string{"*"}, false, "192.168.0.0/16", true},
	{[]string{"*"}, false, "http://example.com", true},
	{[]string{"*"}, false, "example.com:80", true},
	{[]string{"*"}, true, "", false},
	{[]string{"*"}, true, "192.168.1.1", false},
	{[]string{"*"}, true, "192.168.0.0/16", false},
	{[]string{"*"}, true, "http://example.com", false},
	{[]string{"*"}, true, "example.com:80", false},

	// sub-domain
	{[]string{"*.example.com"}, false, "example.com", false},
	{[]string{"*.example.com"}, false, "http://example.com", false},
	{[]string{"*.example.com"}, false, "www.example.com", true},
	{[]string{"*.example.com"}, false, "http://www.example.com", true},
	{[]string{"*.example.com"}, false, "abc.def.example.com", true},

	{[]string{"*.*.example.com"}, false, "example.com", false},
	{[]string{"*.*.example.com"}, false, "www.example.com", false},
	{[]string{"*.*.example.com"}, false, "abc.def.example.com", true},
	{[]string{"*.*.example.com"}, false, "abc.def.ghi.example.com", true},

	{[]string{"**.example.com"}, false, "example.com", false},
	{[]string{"**.example.com"}, false, "www.example.com", true},
	{[]string{"**.example.com"}, false, "abc.def.ghi.example.com", true},

	// prefix wildcard
	{[]string{"*example.com"}, false, "example.com", true},
	{[]string{"*example.com"}, false, "www.example.com", true},
	{[]string{"*example.com"}, false, "abc.defexample.com", true},
	{[]string{"*example.com"}, false, "abc.def-example.com", true},
	{[]string{"*example.com"}, false, "abc.def.example.com", true},
	{[]string{"*example.com"}, false, "http://www.example.com", true},
	{[]string{"*example.com"}, false, "e-xample.com", false},

	{[]string{"http://*.example.com"}, false, "example.com", false},
	{[]string{"http://*.example.com"}, false, "http://example.com", false},
	{[]string{"http://*.example.com"}, false, "http://www.example.com", true},
	{[]string{"http://*.example.com"}, false, "https://www.example.com", false},
	{[]string{"http://*.example.com"}, false, "http://abc.def.example.com", true},

	{[]string{"www.*.com"}, false, "www.example.com", true},
	{[]string{"www.*.com"}, false, "www.abc.def.com", true},

	{[]string{"www.*.*.com"}, false, "www.example.com", false},
	{[]string{"www.*.*.com"}, false, "www.abc.def.com", true},
	{[]string{"www.*.*.com"}, false, "www.abc.def.ghi.com", true},

	{[]string{"www.*example*.com"}, false, "www.example.com", true},
	{[]string{"www.*example*.com"}, false, "www.abc.example.def.com", true},
	{[]string{"www.*example*.com"}, false, "www.e-xample.com", false},

	{[]string{"www.example.*"}, false, "www.example.com", true},
	{[]string{"www.example.*"}, false, "www.example.io", true},
	{[]string{"www.example.*"}, false, "www.example.com.cn", true},

	{[]string{".example.com"}, false, "www.example.com", true},
	{[]string{".example.com"}, false, "example.com", true},
	{[]string{".example.com"}, false, "www.example.com.cn", false},

	{[]string{"example.com*"}, false, "example.com", true},
	{[]string{"example.com:*"}, false, "example.com", false},
	{[]string{"example.com:*"}, false, "example.com:80", false},
	{[]string{"example.com:*"}, false, "example.com:8080", false},
	{[]string{"example.com:*"}, false, "example.com:http", true},
	{[]string{"example.com:*"}, false, "http://example.com:80", false},

	{[]string{"*example.com*"}, false, "example.com:80", true},
	{[]string{"*example.com:*"}, false, "example.com:80", false},

	{[]string{".example.com:*"}, false, "www.example.com", false},
	{[]string{".example.com:*"}, false, "http://www.example.com", false},
	{[]string{".example.com:*"}, false, "example.com:80", false},
	{[]string{".example.com:*"}, false, "www.example.com:8080", false},
	{[]string{".example.com:*"}, false, "http://www.example.com:80", true},
}

func TestBypassContains(t *testing.T) {
	for i, tc := range bypassContainTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			bp := NewBypassPatterns(tc.reversed, tc.patterns...)
			if bp.Contains(tc.addr) != tc.bypassed {
				t.Errorf("#%d test failed: %v, %s", i, tc.patterns, tc.addr)
			}
		})
	}
}

var bypassReloadTests = []struct {
	r io.Reader

	reversed bool
	period   time.Duration

	addr     string
	bypassed bool
	stopped  bool
}{
	{
		r:        nil,
		reversed: false,
		period:   0,
		addr:     "192.168.1.1",
		bypassed: false,
		stopped:  false,
	},
	{
		r:        bytes.NewBufferString(""),
		reversed: false,
		period:   0,
		addr:     "192.168.1.1",
		bypassed: false,
		stopped:  false,
	},
	{
		r:        bytes.NewBufferString("reverse true\nreload 10s"),
		reversed: true,
		period:   10 * time.Second,
		addr:     "192.168.1.1",
		bypassed: false,
		stopped:  false,
	},
	{
		r:        bytes.NewBufferString("reverse false\nreload 10s\n192.168.1.1"),
		reversed: false,
		period:   10 * time.Second,
		addr:     "192.168.1.1",
		bypassed: true,
		stopped:  false,
	},
	{
		r:        bytes.NewBufferString("#reverse true\n#reload 10s\n192.168.0.0/16"),
		reversed: false,
		period:   0,
		addr:     "192.168.10.2",
		bypassed: true,
		stopped:  true,
	},
	{
		r:        bytes.NewBufferString("#reverse true\n#reload 10s\n192.168.1.0/24"),
		reversed: false,
		period:   0,
		addr:     "192.168.10.2",
		bypassed: false,
		stopped:  true,
	},
	{
		r:        bytes.NewBufferString("reverse false\nreload 10s\n192.168.1.1\n#example.com"),
		reversed: false,
		period:   10 * time.Second,
		addr:     "example.com",
		bypassed: false,
		stopped:  false,
	},
	{
		r:        bytes.NewBufferString("#reverse true\n#reload 10s\n192.168.1.1\n#example.com"),
		reversed: false,
		period:   0,
		addr:     "192.168.1.1",
		bypassed: true,
		stopped:  true,
	},
	{
		r:        bytes.NewBufferString("#reverse true\n#reload 10s\nexample.com"),
		reversed: false,
		period:   0,
		addr:     "example.com",
		bypassed: true,
		stopped:  true,
	},
	{
		r:        bytes.NewBufferString("#reverse true\n#reload 10s\n.example.com"),
		reversed: false,
		period:   0,
		addr:     "example.com",
		bypassed: true,
		stopped:  true,
	},
	{
		r:        bytes.NewBufferString("#reverse true\n#reload 10s\n*.example.com"),
		reversed: false,
		period:   0,
		addr:     "example.com",
		bypassed: false,
		stopped:  true,
	},
}

func TestByapssReload(t *testing.T) {
	for i, tc := range bypassReloadTests {
		bp := NewBypass(false)
		if err := bp.Reload(tc.r); err != nil {
			t.Error(err)
		}
		t.Log(bp.String())

		if bp.Reversed() != tc.reversed {
			t.Errorf("#%d test failed: reversed value should be %v, got %v",
				i, tc.reversed, bp.reversed)
		}
		if bp.Period() != tc.period {
			t.Errorf("#%d test failed: period value should be %v, got %v",
				i, tc.period, bp.Period())
		}
		if bp.Contains(tc.addr) != tc.bypassed {
			t.Errorf("#%d test failed: %v, %s", i, bp.reversed, tc.addr)
		}
		if tc.stopped {
			bp.Stop()
			if bp.Period() >= 0 {
				t.Errorf("period of the stopped reloader should be minus value")
			}
			bp.Stop()
		}
		if bp.Stopped() != tc.stopped {
			t.Errorf("#%d test failed: stopped value should be %v, got %v",
				i, tc.stopped, bp.Stopped())
		}
	}
}
