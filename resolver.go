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

type NameServerOption func(*nameServerOptions)

func TimeoutNameServerOption(timeout time.Duration) NameServerOption {
	return func(opts *nameServerOptions) {
		opts.timeout = timeout
	}
}

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

	switch strings.ToLower(ns.Protocol) {
	case "tcp":
		ns.exchanger = NewDNSTCPExchanger(
			ns.Addr,
			TimeoutExchangerOption(ns.options.timeout),
			ChainExchangerOption(ns.options.chain),
		)
	case "tls":
		cfg := &tls.Config{
			ServerName: ns.Hostname,
		}
		if cfg.ServerName == "" {
			cfg.InsecureSkipVerify = true
		}
		ns.exchanger = NewDoTExchanger(
			ns.Addr, cfg,
			TimeoutExchangerOption(ns.options.timeout),
			ChainExchangerOption(ns.options.chain),
		)
	case "https":
		u, err := url.Parse(ns.Addr)
		if err != nil {
			return err
		}
		cfg := &tls.Config{ServerName: u.Hostname()}
		if cfg.ServerName == "" {
			cfg.InsecureSkipVerify = true
		}
		ns.exchanger = NewDoHExchanger(
			u, cfg,
			TimeoutExchangerOption(ns.options.timeout),
			ChainExchangerOption(ns.options.chain),
		)
	case "udp":
		fallthrough
	default:
		ns.exchanger = NewDNSExchanger(
			ns.Addr,
			TimeoutExchangerOption(ns.options.timeout),
			ChainExchangerOption(ns.options.chain),
		)
	}

	return nil
}

func (ns *NameServer) String() string {
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

type resolverOptions struct {
	chain *Chain
}

type ResolverOption func(*resolverOptions)

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
	Servers []NameServer
	mCache  *sync.Map
	TTL     time.Duration
	timeout time.Duration
	period  time.Duration
	domain  string
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
		Servers: servers,
		TTL:     ttl,
		mCache:  &sync.Map{},
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

	var nss []NameServer
	for _, ns := range r.Servers {
		if err := ns.Init( // init all name servers
			ChainNameServerOption(r.options.chain),
			TimeoutNameServerOption(r.timeout),
		); err != nil {
			continue // ignore invalid name servers
		}
		nss = append(nss, ns)
	}

	r.Servers = nss

	return nil
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
			log.Logf("[resolver] %s via %s : %s", host, ns.String(), err)
			continue
		}

		if Debug {
			log.Logf("[resolver] %s via %s %v(ttl: %v)", host, ns.String(), ips, ttl)
		}
		if len(ips) > 0 {
			break
		}
	}

	r.storeCache(host, ips, ttl)
	return
}

func (r *resolver) resolve(ex Exchanger, host string) (ips []net.IP, ttl time.Duration, err error) {
	if ex == nil {
		return
	}

	ctx := context.Background()
	if r.prefer == "ipv6" { // prefer ipv6
		query := dns.Msg{}
		query.SetQuestion(dns.Fqdn(host), dns.TypeAAAA)
		ips, ttl, err = r.resolveIPs(ctx, ex, &query)
		if err != nil || len(ips) > 0 {
			return
		}
	}

	query := dns.Msg{}
	query.SetQuestion(dns.Fqdn(host), dns.TypeA)
	return r.resolveIPs(ctx, ex, &query)
}

func (*resolver) resolveIPs(ctx context.Context, ex Exchanger, query *dns.Msg) (ips []net.IP, ttl time.Duration, err error) {
	// buf := mPool.Get().([]byte)
	// defer mPool.Put(buf)

	//	buf = buf[:0]
	//	mq, err := query.PackBuffer(buf)
	mq, err := query.Pack()
	if err != nil {
		return
	}
	reply, err := ex.Exchange(ctx, mq)
	if err != nil {
		return
	}
	mr := &dns.Msg{}
	if err = mr.Unpack(reply); err != nil {
		return
	}

	for _, ans := range mr.Answer {
		if ar, _ := ans.(*dns.AAAA); ar != nil {
			ips = append(ips, ar.AAAA)
			ttl = time.Duration(ar.Header().Ttl) * time.Second
		}
		if ar, _ := ans.(*dns.A); ar != nil {
			ips = append(ips, ar.A)
			ttl = time.Duration(ar.Header().Ttl) * time.Second
		}
	}
	return
}

func (r *resolver) Exchange(ctx context.Context, query []byte) (reply []byte, err error) {
	if r == nil {
		return
	}

	var servers []NameServer
	r.mux.RLock()
	servers = r.copyServers()
	r.mux.RUnlock()

	for _, ns := range servers {
		reply, err = ns.exchanger.Exchange(ctx, query)
		if err == nil {
			return
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

			if strings.HasPrefix(ns.Addr, "https") {
				ns.Protocol = "https"
			}
			nss = append(nss, ns)
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	r.mux.Lock()
	r.TTL = ttl
	r.timeout = timeout
	r.domain = domain
	r.period = period
	r.prefer = prefer
	r.Servers = nss
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
	Exchange(ctx context.Context, query []byte) ([]byte, error)
}

type exchangerOptions struct {
	chain   *Chain
	timeout time.Duration
}

type ExchangerOption func(opts *exchangerOptions)

func ChainExchangerOption(chain *Chain) ExchangerOption {
	return func(opts *exchangerOptions) {
		opts.chain = chain
	}
}

func TimeoutExchangerOption(timeout time.Duration) ExchangerOption {
	return func(opts *exchangerOptions) {
		opts.timeout = timeout
	}
}

type dnsExchanger struct {
	addr    string
	options exchangerOptions
}

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

func (ex *dnsExchanger) dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	if ex.options.chain.IsEmpty() {
		d := &net.Dialer{
			Timeout: ex.options.timeout,
		}
		return d.DialContext(ctx, network, address)
	}

	raddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return
	}
	cc, err := getSOCKS5UDPTunnel(ex.options.chain, nil)
	conn = &udpTunnelConn{Conn: cc, raddr: raddr}
	return
}

func (ex *dnsExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	c, err := ex.dial(ctx, "udp", ex.addr)
	if err != nil {
		return nil, err
	}

	mq := &dns.Msg{}
	if err = mq.Unpack(query); err != nil {
		return nil, err
	}

	conn := &dns.Conn{
		Conn: c,
	}

	if err = conn.WriteMsg(mq); err != nil {
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

func (ex *dnsTCPExchanger) dial(ctx context.Context, network, address string) (conn net.Conn, err error) {
	if ex.options.chain.IsEmpty() {
		d := &net.Dialer{
			Timeout: ex.options.timeout,
		}
		return d.DialContext(ctx, network, address)
	}
	return ex.options.chain.Dial(address, TimeoutChainOption(ex.options.timeout))
}

func (ex *dnsTCPExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	c, err := ex.dial(ctx, "tcp", ex.addr)
	if err != nil {
		return nil, err
	}

	conn := &dns.Conn{
		Conn: c,
	}

	if _, err = conn.Write(query); err != nil {
		return nil, err
	}

	mr, err := conn.ReadMsg()
	if err != nil {
		log.Log("[dns] exchange", err)
		return nil, err
	}

	return mr.Pack()
}

type dotExchanger struct {
	addr      string
	tlsConfig *tls.Config
	options   exchangerOptions
}

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
	if ex.options.chain.IsEmpty() {
		d := &net.Dialer{
			Timeout: ex.options.timeout,
		}
		conn, err = d.DialContext(ctx, network, address)
	} else {
		conn, err = ex.options.chain.Dial(address, TimeoutChainOption(ex.options.timeout))
	}
	if err == nil {
		conn = tls.Client(conn, ex.tlsConfig)
	}
	return
}

func (ex *dotExchanger) Exchange(ctx context.Context, query []byte) ([]byte, error) {
	c, err := ex.dial(ctx, "tcp", ex.addr)
	if err != nil {
		return nil, err
	}

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

func (ex *dohExchanger) dialContext(ctx context.Context, network, address string) (conn net.Conn, err error) {
	if ex.options.chain.IsEmpty() {
		d := &net.Dialer{
			Timeout: ex.options.timeout,
		}
		return d.DialContext(ctx, network, address)
	}
	return ex.options.chain.Dial(address, TimeoutChainOption(ex.options.timeout))
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
