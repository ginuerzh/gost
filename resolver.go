package gost

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-log/log"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

var (
	// DefaultResolverTimeout is the default timeout for name resolution.
	DefaultResolverTimeout = 5 * time.Second
)

// Resolver is a name resolver for domain name.
// It contains a list of name servers.
type Resolver interface {
	// Resolve returns a slice of that host's IPv4 and IPv6 addresses.
	Resolve(host string) ([]net.IP, error)
}

// ReloadResolver is resolover that support live reloading.
type ReloadResolver interface {
	Resolver
	Reloader
	Stoppable
}

// NameServer is a name server.
// Currently supported protocol: TCP, UDP and TLS.
type NameServer struct {
	Addr      string
	Protocol  string
	Hostname  string // for TLS handshake verification
	Timeout   time.Duration
	exchanger Exchanger
}

// Init initializes the name server.
func (ns *NameServer) Init() error {
	timeout := ns.Timeout
	if timeout <= 0 {
		timeout = DefaultResolverTimeout
	}

	switch strings.ToLower(ns.Protocol) {
	case "tcp":
		ns.exchanger = &dnsExchanger{
			endpoint: ns.Addr,
			client: &dns.Client{
				Net:     "tcp",
				Timeout: timeout,
			},
		}
	case "tls":
		cfg := &tls.Config{
			ServerName: ns.Hostname,
		}
		if cfg.ServerName == "" {
			cfg.InsecureSkipVerify = true
		}

		ns.exchanger = &dnsExchanger{
			endpoint: ns.Addr,
			client: &dns.Client{
				Net:       "tcp-tls",
				Timeout:   timeout,
				TLSConfig: cfg,
			},
		}
	case "https":
		u, err := url.Parse(ns.Addr)
		if err != nil {
			return err
		}
		cfg := &tls.Config{ServerName: u.Hostname()}
		transport := &http.Transport{
			TLSClientConfig:    cfg,
			DisableCompression: true,
			MaxIdleConns:       1,
		}
		http2.ConfigureTransport(transport)

		ns.exchanger = &dohExchanger{
			endpoint: u,
			client: &http.Client{
				Transport: transport,
				Timeout:   timeout,
			},
		}
	case "udp":
		fallthrough
	default:
		ns.exchanger = &dnsExchanger{
			endpoint: ns.Addr,
			client: &dns.Client{
				Net:     "udp",
				Timeout: timeout,
			},
		}
	}

	return nil
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

type resolver struct {
	Servers []NameServer
	mCache  *sync.Map
	TTL     time.Duration
	period  time.Duration
	domain  string
	stopped chan struct{}
	mux     sync.RWMutex
}

// NewResolver create a new Resolver with the given name servers and resolution timeout.
func NewResolver(ttl time.Duration, servers ...NameServer) ReloadResolver {
	r := newResolver(ttl, servers...)
	return r
}

func newResolver(ttl time.Duration, servers ...NameServer) *resolver {
	return &resolver{
		Servers: servers,
		TTL:     ttl,
		mCache:  &sync.Map{},
		stopped: make(chan struct{}),
	}
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
	var ttl time.Duration
	var servers []NameServer

	r.mux.RLock()
	domain = r.domain
	ttl = r.TTL
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
		ips, ttl, err = r.resolve(ns.exchanger, host)
		if err != nil {
			log.Logf("[resolver] %s via %s : %s", host, ns, err)
			continue
		}

		if Debug {
			log.Logf("[resolver] %s via %s %v(ttl: %v)", host, ns, ips, ttl)
		}
		if len(ips) > 0 {
			break
		}
	}

	r.storeCache(host, ips, ttl)
	return
}

func (*resolver) resolve(ex Exchanger, host string) (ips []net.IP, ttl time.Duration, err error) {
	if ex == nil {
		return
	}

	query := dns.Msg{}
	query.SetQuestion(dns.Fqdn(host), dns.TypeA)
	mr, err := ex.Exchange(context.Background(), &query)
	if err != nil {
		return
	}
	for _, ans := range mr.Answer {
		if ar, _ := ans.(*dns.A); ar != nil {
			ips = append(ips, ar.A)
			ttl = time.Duration(ar.Header().Ttl) * time.Second
		}
	}
	return
}

type resolverCacheItem struct {
	IPs []net.IP
	ts  int64
	ttl time.Duration
}

func (r *resolver) loadCache(name string, ttl time.Duration) []net.IP {
	if name == "" || ttl < 0 {
		return nil
	}

	if v, ok := r.mCache.Load(name); ok {
		item, _ := v.(*resolverCacheItem)
		if ttl == 0 {
			ttl = item.ttl
		}

		if time.Since(time.Unix(item.ts, 0)) > ttl {
			r.mCache.Delete(name)
			return nil
		}
		return item.IPs
	}

	return nil
}

func (r *resolver) storeCache(name string, ips []net.IP, ttl time.Duration) {
	if name == "" || len(ips) == 0 || ttl < 0 {
		return
	}
	r.mCache.Store(name, &resolverCacheItem{
		IPs: ips,
		ts:  time.Now().Unix(),
		ttl: ttl,
	})
}

func (r *resolver) Reload(rd io.Reader) error {
	var ttl, timeout, period time.Duration
	var domain string
	var nss []NameServer

	if rd == nil || r.Stopped() {
		return nil
	}

	scanner := bufio.NewScanner(rd)
	for scanner.Scan() {
		line := scanner.Text()
		ss := splitLine(line)
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

			if strings.HasPrefix(ns.Addr, "https") {
				ns.Protocol = "https"
			}
			ns.Timeout = timeout

			if err := ns.Init(); err == nil {
				nss = append(nss, ns)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	r.mux.Lock()
	r.TTL = ttl
	r.domain = domain
	r.period = period
	r.Servers = nss
	r.mux.Unlock()

	return nil
}

func (r *resolver) Period() time.Duration {
	if r.Stopped() {
		return -1
	}

	r.mux.RLock()
	defer r.mux.RUnlock()

	return r.period
}

// Stop stops reloading.
func (r *resolver) Stop() {
	select {
	case <-r.stopped:
	default:
		close(r.stopped)
	}
}

// Stopped checks whether the reloader is stopped.
func (r *resolver) Stopped() bool {
	select {
	case <-r.stopped:
		return true
	default:
		return false
	}
}

func (r *resolver) String() string {
	if r == nil {
		return ""
	}

	r.mux.RLock()
	defer r.mux.RUnlock()

	b := &bytes.Buffer{}
	fmt.Fprintf(b, "TTL %v\n", r.TTL)
	fmt.Fprintf(b, "Reload %v\n", r.period)
	fmt.Fprintf(b, "Domain %v\n", r.domain)
	for i := range r.Servers {
		fmt.Fprintln(b, r.Servers[i])
	}
	return b.String()
}

// Exchanger is an interface for DNS synchronous query.
type Exchanger interface {
	Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error)
}

type dnsExchanger struct {
	endpoint string
	client   *dns.Client
}

func (ex *dnsExchanger) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	ep := ex.endpoint
	if _, port, _ := net.SplitHostPort(ep); port == "" {
		ep = net.JoinHostPort(ep, "53")
	}
	mr, _, err := ex.client.Exchange(query, ep)
	return mr, err
}

type dohExchanger struct {
	endpoint *url.URL
	client   *http.Client
}

// reference: https://github.com/cloudflare/cloudflared/blob/master/tunneldns/https_upstream.go#L54
func (ex *dohExchanger) Exchange(ctx context.Context, query *dns.Msg) (*dns.Msg, error) {
	queryBuf, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS query: %s", err)
	}

	// No content negotiation for now, use DNS wire format
	buf, backendErr := ex.exchangeWireformat(queryBuf)
	if backendErr == nil {
		response := &dns.Msg{}
		if err := response.Unpack(buf); err != nil {
			return nil, fmt.Errorf("failed to unpack DNS response from body: %s", err)
		}

		response.Id = query.Id
		return response, nil
	}

	return nil, backendErr
}

// Perform message exchange with the default UDP wireformat defined in current draft
// https://datatracker.ietf.org/doc/draft-ietf-doh-dns-over-https
func (ex *dohExchanger) exchangeWireformat(msg []byte) ([]byte, error) {
	req, err := http.NewRequest("POST", ex.endpoint.String(), bytes.NewBuffer(msg))
	if err != nil {
		return nil, fmt.Errorf("failed to create an HTTPS request: %s", err)
	}

	req.Header.Add("Content-Type", "application/dns-udpwireformat")
	req.Host = ex.endpoint.Hostname()

	resp, err := ex.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform an HTTPS request: %s", err)
	}

	// Check response status code
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned status code %d", resp.StatusCode)
	}

	// Read wireformat response from the body
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read the response body: %s", err)
	}

	return buf, nil
}
