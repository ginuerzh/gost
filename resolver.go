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
)

var (
	// DefaultResolverTimeout is the default timeout for name resolution.
	DefaultResolverTimeout = 5 * time.Second
)

type nameServerOptions struct {
	timeout time.Duration
	chain   *Chain
}

// NameServerOption allows a common way to set name server options.
type NameServerOption func(*nameServerOptions)

// TimeoutNameServerOption sets the timeout for name server.
func TimeoutNameServerOption(timeout time.Duration) NameServerOption {
	return func(opts *nameServerOptions) {
		opts.timeout = timeout
	}
}

// ChainNameServerOption sets the chain for name server.
func ChainNameServerOption(chain *Chain) NameServerOption {
	return func(opts *nameServerOptions) {
		opts.chain = chain
	}
}

// NameServer is a name server.
// Currently supported protocol: TCP, UDP and TLS.
type NameServer struct {
	Addr      string
	Protocol  string
	Hostname  string // for TLS handshake verification
	exchanger Exchanger
	options   nameServerOptions
}

// Init initializes the name server.
func (ns *NameServer) Init(opts ...NameServerOption) error {
	for _, opt := range opts {
		opt(&ns.options)
	}

	options := []ExchangerOption{
		TimeoutExchangerOption(ns.options.timeout),
	}
	protocol := strings.ToLower(ns.Protocol)
	switch protocol {
	case "tcp", "tcp-chain":
		if protocol == "tcp-chain" {
			options = append(options, ChainExchangerOption(ns.options.chain))
		}
		ns.exchanger = NewDNSTCPExchanger(ns.Addr, options...)
	case "tls", "tls-chain":
		if protocol == "tls-chain" {
			options = append(options, ChainExchangerOption(ns.options.chain))
		}
		cfg := &tls.Config{
			ServerName: ns.Hostname,
		}
		if cfg.ServerName == "" {
			cfg.InsecureSkipVerify = true
		}
		ns.exchanger = NewDoTExchanger(ns.Addr, cfg, options...)
	case "https", "https-chain":
		if protocol == "https-chain" {
			options = append(options, ChainExchangerOption(ns.options.chain))
		}
		u, err := url.Parse(ns.Addr)
		if err != nil {
			return err
		}
		u.Scheme = "https"
		cfg := &tls.Config{ServerName: ns.Hostname}
		if cfg.ServerName == "" {
			cfg.InsecureSkipVerify = true
		}
		ns.exchanger = NewDoHExchanger(u, cfg, options...)
	case "udp", "udp-chain":
		fallthrough
	default:
		if protocol == "udp-chain" {
			options = append(options, ChainExchangerOption(ns.options.chain))
		}
		ns.exchanger = NewDNSExchanger(ns.Addr, options...)
	}

	return nil
}

func (ns *NameServer) String() string {
	addr := ns.Addr
	prot := ns.Protocol
	if prot == "" {
		prot = "udp"
	}
	return fmt.Sprintf("%s/%s", addr, prot)
}

type resolverOptions struct {
	chain *Chain
}

// ResolverOption allows a common way to set Resolver options.
type ResolverOption func(*resolverOptions)

// ChainResolverOption sets the chain for Resolver.
func ChainResolverOption(chain *Chain) ResolverOption {
	return func(opts *resolverOptions) {
		opts.chain = chain
	}
}

// Resolver is a name resolver for domain name.
// It contains a list of name servers.
type Resolver interface {
	// Init initializes the Resolver instance.
	Init(opts ...ResolverOption) error
	// Resolve returns a slice of that host's IPv4 and IPv6 addresses.
	Resolve(host string) ([]net.IP, error)
	// Exchange performs a synchronous query,
	// It sends the message query and waits for a reply.
	Exchange(ctx context.Context, query []byte) (reply []byte, err error)
}

// ReloadResolver is resolover that support live reloading.
type ReloadResolver interface {
	Resolver
	Reloader
	Stoppable
}

type resolver struct {
	servers []NameServer
	ttl     time.Duration
	timeout time.Duration
	period  time.Duration
	domain  string
	cache   *resolverCache
	stopped chan struct{}
	mux     sync.RWMutex
	prefer  string // ipv4 or ipv6
	options resolverOptions
}

// NewResolver create a new Resolver with the given name servers and resolution timeout.
func NewResolver(ttl time.Duration, servers ...NameServer) ReloadResolver {
	r := newResolver(ttl, servers...)
	return r
}

func newResolver(ttl time.Duration, servers ...NameServer) *resolver {
	return &resolver{
		servers: servers,
		cache:   newResolverCache(ttl),
		stopped: make(chan struct{}),
	}
}

func (r *resolver) Init(opts ...ResolverOption) error {
	if r == nil {
		return nil
	}

	r.mux.Lock()
	defer r.mux.Unlock()

	for _, opt := range opts {
		opt(&r.options)
	}

	timeout := r.timeout
	if timeout <= 0 {
		timeout = DefaultResolverTimeout
	}

	var nss []NameServer
	for _, ns := range r.servers {
		if err := ns.Init( // init all name servers
			ChainNameServerOption(r.options.chain),
			TimeoutNameServerOption(timeout),
		); err != nil {
			continue // ignore invalid name servers
		}
		nss = append(nss, ns)
	}

	r.servers = nss

	return nil
}

func (r *resolver) copyServers() []NameServer {
	r.mux.RLock()
	defer r.mux.RUnlock()

	servers := make([]NameServer, len(r.servers))
	for i := range r.servers {
		servers[i] = r.servers[i]
	}

	return servers
}

func (r *resolver) Resolve(host string) (ips []net.IP, err error) {
	r.mux.RLock()
	domain := r.domain
	r.mux.RUnlock()

	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	if !strings.Contains(host, ".") && domain != "" {
		host = host + "." + domain
	}

	for _, ns := range r.copyServers() {
		ips, err = r.resolve(ns.exchanger, host)
		if err != nil {
			log.Logf("[resolver] %s via %s : %s", host, ns.String(), err)
			continue
		}

		if Debug {
			log.Logf("[resolver] %s via %s %v", host, ns.String(), ips)
		}
		if len(ips) > 0 {
			break
		}
	}

	return
}

func (r *resolver) resolve(ex Exchanger, host string) (ips []net.IP, err error) {
	if ex == nil {
		return
	}

	r.mux.RLock()
	prefer := r.prefer
	r.mux.RUnlock()

	ctx := context.Background()
	if prefer == "ipv6" { // prefer ipv6
		mq := &dns.Msg{}
		mq.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		ips, err = r.resolveIPs(ctx, ex, mq)
		if err != nil || len(ips) > 0 {
			return
		}
	}

	mq := &dns.Msg{}
	mq.SetQuestion(dns.Fqdn(host), dns.TypeA)
	return r.resolveIPs(ctx, ex, mq)
}

func (r *resolver) resolveIPs(ctx context.Context, ex Exchanger, mq *dns.Msg) (ips []net.IP, err error) {
	mr, err := r.exchangeMsg(ctx, ex, mq)
	if err != nil {
		return
	}

	for _, ans := range mr.Answer {
		if ar, _ := ans.(*dns.AAAA); ar != nil {
			ips = append(ips, ar.AAAA)
		}
		if ar, _ := ans.(*dns.A); ar != nil {
			ips = append(ips, ar.A)
		}
	}

	return
}

func (r *resolver) Exchange(ctx context.Context, query []byte) (reply []byte, err error) {
	mq := &dns.Msg{}
	if err = mq.Unpack(query); err != nil {
		return
	}

	var mr *dns.Msg
	for _, ns := range r.copyServers() {
		mr, err = r.exchangeMsg(ctx, ns.exchanger, mq)
		if err == nil {
			break
		}
	}
	if err != nil {
		return
	}
	return mr.Pack()
}

func (r *resolver) exchangeMsg(ctx context.Context, ex Exchanger, mq *dns.Msg) (mr *dns.Msg, err error) {
	// Only cache for single question.
	if len(mq.Question) == 1 {
		key := newResolverCacheKey(&mq.Question[0])
		mr = r.cache.loadCache(key)
		if mr != nil {
			mr.Id = mq.Id
			return
		}

		defer func() {
			r.cache.storeCache(key, mr, r.TTL())
		}()
	}

	query, err := mq.Pack()
	if err != nil {
		return
	}
	reply, err := ex.Exchange(ctx, query)
	if err != nil {
		return
	}

	mr = &dns.Msg{}
	if err = mr.Unpack(reply); err != nil {
		return nil, err
	}

	return
}

func (r *resolver) TTL() time.Duration {
	r.mux.RLock()
	defer r.mux.RUnlock()
	return r.ttl
}

func (r *resolver) Reload(rd io.Reader) error {
	var ttl, timeout, period time.Duration
	var domain, prefer string
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
		case "prefer":
			if len(ss) > 1 {
				prefer = strings.ToLower(ss[1])
			}
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

			if strings.HasPrefix(ns.Addr, "https") && ns.Protocol == "" {
				ns.Protocol = "https"
			}
			nss = append(nss, ns)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	r.mux.Lock()
	r.ttl = ttl
	r.timeout = timeout
	r.domain = domain
	r.period = period
	r.prefer = prefer
	r.servers = nss
	r.mux.Unlock()

	r.Init()

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
	fmt.Fprintf(b, "TTL %v\n", r.ttl)
	fmt.Fprintf(b, "Reload %v\n", r.period)
	fmt.Fprintf(b, "Domain %v\n", r.domain)
	for i := range r.servers {
		fmt.Fprintln(b, r.servers[i])
	}
	return b.String()
}

type resolverCacheKey string

// newResolverCacheKey generates resolver cache key from question of dns query.
func newResolverCacheKey(q *dns.Question) resolverCacheKey {
	if q == nil {
		return ""
	}
	key := fmt.Sprintf("%s%s.%s", q.Name, dns.Class(q.Qclass).String(), dns.Type(q.Qtype).String())
	return resolverCacheKey(key)
}

type resolverCacheItem struct {
	mr  *dns.Msg
	ts  int64
	ttl time.Duration
}

type resolverCache struct {
	m sync.Map
}

func newResolverCache(ttl time.Duration) *resolverCache {
	return &resolverCache{}
}

func (rc *resolverCache) loadCache(key resolverCacheKey) *dns.Msg {
	v, ok := rc.m.Load(key)
	if !ok {
		return nil
	}

	item, ok := v.(*resolverCacheItem)
	if !ok {
		return nil
	}

	elapsed := time.Since(time.Unix(item.ts, 0))
	if item.ttl > 0 && elapsed > item.ttl {
		rc.m.Delete(key)
		return nil
	}
	for _, rr := range item.mr.Answer {
		if elapsed > time.Duration(rr.Header().Ttl)*time.Second {
			rc.m.Delete(key)
			return nil
		}
	}

	if Debug {
		log.Logf("[resolver] cache hit %s", key)
	}

	return item.mr.Copy()
}

func (rc *resolverCache) storeCache(key resolverCacheKey, mr *dns.Msg, ttl time.Duration) {
	if key == "" || mr == nil || ttl < 0 {
		return
	}

	rc.m.Store(key, &resolverCacheItem{
		mr:  mr.Copy(),
		ts:  time.Now().Unix(),
		ttl: ttl,
	})
	if Debug {
		log.Logf("[resolver] cache store %s", key)
	}
}

// Exchanger is an interface for DNS synchronous query.
type Exchanger interface {
	Exchange(ctx context.Context, query []byte) ([]byte, error)
}

type exchangerOptions struct {
	chain   *Chain
	timeout time.Duration
}

// ExchangerOption allows a common way to set Exchanger options.
type ExchangerOption func(opts *exchangerOptions)

// ChainExchangerOption sets the chain for Exchanger.
func ChainExchangerOption(chain *Chain) ExchangerOption {
	return func(opts *exchangerOptions) {
		opts.chain = chain
	}
}

// TimeoutExchangerOption sets the timeout for Exchanger.
func TimeoutExchangerOption(timeout time.Duration) ExchangerOption {
	return func(opts *exchangerOptions) {
		opts.timeout = timeout
	}
}

type dnsExchanger struct {
	addr    string
	options exchangerOptions
}

// NewDNSExchanger creates a DNS over UDP Exchanger
func NewDNSExchanger(addr string, opts ...ExchangerOption) Exchanger {
	var options exchangerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "53")
	}

	return &dnsExchanger{
		addr:    addr,
		options: options,
	}
}

func (ex *dnsExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	t := time.Now()
	c, err := ex.options.chain.DialContext(ctx,
		"udp", ex.addr,
		TimeoutChainOption(ex.options.timeout),
	)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(ex.options.timeout - time.Since(t)))
	defer c.Close()

	conn := &dns.Conn{
		Conn: c,
	}
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}

	mr, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}

	return mr.Pack()
}

type dnsTCPExchanger struct {
	addr    string
	options exchangerOptions
}

// NewDNSTCPExchanger creates a DNS over TCP Exchanger
func NewDNSTCPExchanger(addr string, opts ...ExchangerOption) Exchanger {
	var options exchangerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "53")
	}

	return &dnsTCPExchanger{
		addr:    addr,
		options: options,
	}
}

func (ex *dnsTCPExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	t := time.Now()
	c, err := ex.options.chain.DialContext(ctx,
		"tcp", ex.addr,
		TimeoutChainOption(ex.options.timeout),
	)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(ex.options.timeout - time.Since(t)))
	defer c.Close()

	conn := &dns.Conn{
		Conn: c,
	}
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}

	mr, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}

	return mr.Pack()
}

type dotExchanger struct {
	addr      string
	tlsConfig *tls.Config
	options   exchangerOptions
}

// NewDoTExchanger creates a DNS over TLS Exchanger
func NewDoTExchanger(addr string, tlsConfig *tls.Config, opts ...ExchangerOption) Exchanger {
	var options exchangerOptions
	for _, opt := range opts {
		opt(&options)
	}

	if _, port, _ := net.SplitHostPort(addr); port == "" {
		addr = net.JoinHostPort(addr, "53")
	}

	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}
	return &dotExchanger{
		addr:      addr,
		tlsConfig: tlsConfig,
		options:   options,
	}
}

func (ex *dotExchanger) dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	conn, err = ex.options.chain.DialContext(ctx,
		network, address,
		TimeoutChainOption(ex.options.timeout),
	)
	if err != nil {
		return
	}
	conn = tls.Client(conn, ex.tlsConfig)

	return
}

func (ex *dotExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	t := time.Now()
	c, err := ex.dial(ctx, "tcp", ex.addr)
	if err != nil {
		return nil, err
	}
	c.SetDeadline(time.Now().Add(ex.options.timeout - time.Since(t)))
	defer c.Close()

	conn := &dns.Conn{
		Conn: c,
	}
	if _, err = conn.Write(query); err != nil {
		return nil, err
	}

	mr, err := conn.ReadMsg()
	if err != nil {
		return nil, err
	}

	return mr.Pack()
}

type dohExchanger struct {
	endpoint *url.URL
	client   *http.Client
	options  exchangerOptions
}

// NewDoHExchanger creates a DNS over HTTPS Exchanger
func NewDoHExchanger(urlStr *url.URL, tlsConfig *tls.Config, opts ...ExchangerOption) Exchanger {
	var options exchangerOptions
	for _, opt := range opts {
		opt(&options)
	}
	ex := &dohExchanger{
		endpoint: urlStr,
		options:  options,
	}

	ex.client = &http.Client{
		Timeout: options.timeout,
		Transport: &http.Transport{
			// Proxy: ProxyFromEnvironment,
			TLSClientConfig:       tlsConfig,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   options.timeout,
			ExpectContinueTimeout: 1 * time.Second,
			DialContext:           ex.dialContext,
		},
	}

	return ex
}

func (ex *dohExchanger) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return ex.options.chain.DialContext(ctx,
		network, address,
		TimeoutChainOption(ex.options.timeout),
	)
}

func (ex *dohExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", ex.endpoint.String(), bytes.NewBuffer(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create an HTTPS request: %s", err)
	}

	// req.Header.Add("Content-Type", "application/dns-udpwireformat")
	req.Header.Add("Content-Type", "application/dns-message")
	req.Host = ex.endpoint.Hostname()

	client := ex.client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
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
