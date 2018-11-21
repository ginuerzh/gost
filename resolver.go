package gost

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-log/log"
	"github.com/miekg/dns"
)

var (
	// DefaultResolverTimeout is the default timeout for name resolution.
	DefaultResolverTimeout = 30 * time.Second
	// DefaultResolverTTL is the default cache TTL for name resolution.
	DefaultResolverTTL = 60 * time.Second
)

// Resolver is a name resolver for domain name.
// It contains a list of name servers.
type Resolver interface {
	// Resolve returns a slice of that host's IPv4 and IPv6 addresses.
	Resolve(host string) ([]net.IP, error)
}

// ReloadResolver is resolover that support live reloading
type ReloadResolver interface {
	Resolver
	Reloader
}

// NameServer is a name server.
// Currently supported protocol: TCP, UDP and TLS.
type NameServer struct {
	Addr     string
	Protocol string
	Hostname string // for TLS handshake verification
}

func (ns NameServer) String() string {
	addr := ns.Addr
	prot := ns.Protocol
	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "53")
	}
	if prot == "" {
		prot = "udp"
	}
	return fmt.Sprintf("%s/%s", addr, prot)
}

type resolverCacheItem struct {
	IPs []net.IP
	ts  int64
}

type resolver struct {
	Resolver *net.Resolver
	Servers  []NameServer
	mCache   *sync.Map
	Timeout  time.Duration
	TTL      time.Duration
	period   time.Duration
	domain   string
	mux      sync.RWMutex
}

// NewResolver create a new Resolver with the given name servers and resolution timeout.
func NewResolver(timeout, ttl time.Duration, servers ...NameServer) ReloadResolver {
	r := &resolver{
		Servers: servers,
		Timeout: timeout,
		TTL:     ttl,
		mCache:  &sync.Map{},
	}

	if r.Timeout <= 0 {
		r.Timeout = DefaultResolverTimeout
	}
	if r.TTL == 0 {
		r.TTL = DefaultResolverTTL
	}
	return r
}

func (r *resolver) copyServers() []NameServer {
	var servers []NameServer
	for i := range r.Servers {
		servers = append(servers, r.Servers[i])
	}

	return servers
}

func (r *resolver) Resolve(host string) (ips []net.IP, err error) {
	if r == nil {
		return
	}

	var domain string
	var timeout, ttl time.Duration
	var servers []NameServer

	r.mux.RLock()
	domain = r.domain
	timeout = r.Timeout
	servers = r.copyServers()
	r.mux.RUnlock()

	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	if !strings.Contains(host, ".") && domain != "" {
		host = host + "." + domain
	}
	ips = r.loadCache(host, ttl)
	if len(ips) > 0 {
		if Debug {
			log.Logf("[resolver] cache hit %s: %v", host, ips)
		}
		return
	}

	for _, ns := range servers {
		ips, err = r.resolve(ns, host, timeout)
		if err != nil {
			log.Logf("[resolver] %s via %s : %s", host, ns, err)
			continue
		}

		if Debug {
			log.Logf("[resolver] %s via %s %v", host, ns, ips)
		}
		if len(ips) > 0 {
			break
		}
	}

	r.storeCache(host, ips)
	return
}

func (*resolver) resolve(ns NameServer, host string, timeout time.Duration) (ips []net.IP, err error) {
	addr := ns.Addr
	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "53")
	}

	client := dns.Client{
		Timeout: timeout,
	}
	switch strings.ToLower(ns.Protocol) {
	case "tcp":
		client.Net = "tcp"
	case "tls":
		cfg := &tls.Config{
			ServerName: ns.Hostname,
		}
		if cfg.ServerName == "" {
			cfg.InsecureSkipVerify = true
		}
		client.Net = "tcp-tls"
		client.TLSConfig = cfg
	case "udp":
		fallthrough
	default:
		client.Net = "udp"
	}

	m := dns.Msg{}
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	mr, _, err := client.Exchange(&m, addr)
	if err != nil {
		return
	}
	for _, ans := range mr.Answer {
		if ar, _ := ans.(*dns.A); ar != nil {
			ips = append(ips, ar.A)
		}
	}
	return
}

func (r *resolver) loadCache(name string, ttl time.Duration) []net.IP {
	if ttl < 0 {
		return nil
	}

	if v, ok := r.mCache.Load(name); ok {
		item, _ := v.(*resolverCacheItem)
		if item == nil || time.Since(time.Unix(item.ts, 0)) > ttl {
			return nil
		}
		return item.IPs
	}

	return nil
}

func (r *resolver) storeCache(name string, ips []net.IP) {
	if name == "" || len(ips) == 0 {
		return
	}
	r.mCache.Store(name, &resolverCacheItem{
		IPs: ips,
		ts:  time.Now().Unix(),
	})
}

func (r *resolver) Reload(rd io.Reader) error {
	var ttl, timeout, period time.Duration
	var domain string
	var nss []NameServer

	split := func(line string) []string {
		if line == "" {
			return nil
		}
		if n := strings.IndexByte(line, '#'); n >= 0 {
			line = line[:n]
		}
		line = strings.Replace(line, "\t", " ", -1)
		line = strings.TrimSpace(line)

		var ss []string
		for _, s := range strings.Split(line, " ") {
			if s = strings.TrimSpace(s); s != "" {
				ss = append(ss, s)
			}
		}
		return ss
	}

	scanner := bufio.NewScanner(rd)
	for scanner.Scan() {
		line := scanner.Text()
		ss := split(line)
		if len(ss) == 0 {
			continue
		}

		switch ss[0] {
		case "timeout": // timeout option
			if len(ss) > 1 {
				timeout, _ = time.ParseDuration(ss[1])
			}
		case "ttl": // ttl option
			if len(ss) > 1 {
				ttl, _ = time.ParseDuration(ss[1])
			}
		case "reload": // reload option
			if len(ss) > 1 {
				period, _ = time.ParseDuration(ss[1])
			}
		case "domain":
			if len(ss) > 1 {
				domain = ss[1]
			}
		case "search", "sortlist", "options": // we don't support these features in /etc/resolv.conf
		case "nameserver": // nameserver option, compatible with /etc/resolv.conf
			if len(ss) <= 1 {
				break
			}
			ss = ss[1:]
			fallthrough
		default:
			var ns NameServer
			switch len(ss) {
			case 0:
				break
			case 1:
				ns.Addr = ss[0]
			case 2:
				ns.Addr = ss[0]
				ns.Protocol = ss[1]
			default:
				ns.Addr = ss[0]
				ns.Protocol = ss[1]
				ns.Hostname = ss[2]
			}
			nss = append(nss, ns)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	r.mux.Lock()
	r.Timeout = timeout
	r.TTL = ttl
	r.domain = domain
	r.period = period
	r.Servers = nss
	r.mux.Unlock()

	return nil
}

func (r *resolver) Period() time.Duration {
	r.mux.RLock()
	defer r.mux.RUnlock()

	return r.period
}

func (r *resolver) String() string {
	if r == nil {
		return ""
	}

	r.mux.RLock()
	defer r.mux.RUnlock()

	b := &bytes.Buffer{}
	fmt.Fprintf(b, "Timeout %v\n", r.Timeout)
	fmt.Fprintf(b, "TTL %v\n", r.TTL)
	fmt.Fprintf(b, "Reload %v\n", r.period)
	for i := range r.Servers {
		fmt.Fprintln(b, r.Servers[i])
	}
	return b.String()
}
