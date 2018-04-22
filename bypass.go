package gost

import (
	"net"

	glob "github.com/gobwas/glob"
)

// Matcher is a generic pattern matcher,
// it gives the match result of the given pattern for specific v.
type Matcher interface {
	Match(v string) bool
}

// NewMatcher creates a Matcher for the given pattern.
// The acutal Matcher depends on the pattern:
// IP Matcher if pattern is a valid IP address.
// CIDR Matcher if pattern is a valid CIDR address.
// Domain Matcher if both of the above are not.
func NewMatcher(pattern string) Matcher {
	if pattern == "" {
		return nil
	}
	if ip := net.ParseIP(pattern); ip != nil {
		return IPMatcher(ip)
	}
	if _, inet, err := net.ParseCIDR(pattern); err == nil {
		return CIDRMatcher(inet)
	}
	return DomainMatcher(pattern)
}

type ipMatcher struct {
	ip net.IP
}

// IPMatcher creates a Matcher for a specific IP address.
func IPMatcher(ip net.IP) Matcher {
	return &ipMatcher{
		ip: ip,
	}
}

func (m *ipMatcher) Match(ip string) bool {
	if m == nil {
		return false
	}
	return m.ip.Equal(net.ParseIP(ip))
}

type cidrMatcher struct {
	ipNet *net.IPNet
}

// CIDRMatcher creates a Matcher for a specific CIDR notation IP address.
func CIDRMatcher(inet *net.IPNet) Matcher {
	return &cidrMatcher{
		ipNet: inet,
	}
}

func (m *cidrMatcher) Match(ip string) bool {
	if m == nil || m.ipNet == nil {
		return false
	}
	return m.ipNet.Contains(net.ParseIP(ip))
}

type domainMatcher struct {
	glob glob.Glob
}

// DomainMatcher creates a Matcher for a specific domain pattern,
// the pattern can be a plain domain such as 'example.com'
// or a wildcard such as '*.exmaple.com'.
func DomainMatcher(pattern string) Matcher {
	return &domainMatcher{
		glob: glob.MustCompile(pattern),
	}
}

func (m *domainMatcher) Match(domain string) bool {
	if m == nil || m.glob == nil {
		return false
	}
	return m.glob.Match(domain)
}

// Bypass is a filter for address (IP or domain).
// It contains a list of matchers.
type Bypass struct {
	matchers []Matcher
	reverse  bool
}

// NewBypass creates and initializes a new Bypass using matchers as its match rules.
// The rules will be reversed if the reversed is true.
func NewBypass(matchers []Matcher, reverse bool) *Bypass {
	return &Bypass{
		matchers: matchers,
		reverse:  reverse,
	}
}

// NewBypassPatterns creates and initializes a new Bypass using matcher patterns as its match rules.
// The rules will be reversed if the reverse is true.
func NewBypassPatterns(patterns []string, reverse bool) *Bypass {
	var matchers []Matcher
	for _, pattern := range patterns {
		if pattern != "" {
			matchers = append(matchers, NewMatcher(pattern))
		}
	}
	return NewBypass(matchers, reverse)
}

// Contains reports whether the bypass includes addr.
func (bp *Bypass) Contains(addr string) bool {
	for _, matcher := range bp.matchers {
		if matcher == nil {
			continue
		}
		matched := matcher.Match(addr)
		if (matched && !bp.reverse) ||
			(!matched && bp.reverse) {
			return true
		}
	}
	return false
}
