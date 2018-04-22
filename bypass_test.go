package gost

import "testing"

var bypassTests = []struct {
	patterns []string
	reversed bool
	addr     string
	bypassed bool
}{
	// IP address
	{[]string{"192.168.1.1"}, false, "192.168.1.1", true},
	{[]string{"192.168.1.1"}, false, "192.168.1.2", false},
	{[]string{"0.0.0.0"}, false, "0.0.0.0", true},

	// CIDR address
	{[]string{"192.168.1.0/0"}, false, "1.2.3.4", true},
	{[]string{"192.168.1.0/8"}, false, "192.1.0.255", true},
	{[]string{"192.168.1.0/16"}, false, "192.168.0.255", true},
	{[]string{"192.168.1.0/24"}, false, "192.168.1.255", true},
	{[]string{"192.168.1.1/32"}, false, "192.168.1.1", true},
	{[]string{"192.168.1.1/32"}, false, "192.168.1.2", false},

	// plain domain
	{[]string{"www.example.com"}, false, "www.example.com", true},
	{[]string{"http://www.example.com"}, false, "http://www.example.com", true},
	{[]string{"http://www.example.com"}, false, "http://example.com", false},
	{[]string{"www.example.com"}, false, "example.com", false},

	// domain wildcard

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
}

func TestBypass(t *testing.T) {
	for i, test := range bypassTests {
		bp := NewBypassPatterns(test.patterns, test.reversed)
		if bp.Contains(test.addr) != test.bypassed {
			t.Errorf("test %d failed", i)
		}

		rbp := NewBypassPatterns(test.patterns, !test.reversed)
		if rbp.Contains(test.addr) == test.bypassed {
			t.Errorf("reverse test %d failed", i)
		}
	}
}
