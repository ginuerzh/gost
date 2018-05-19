package gost

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-log/log"
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
	Resolve(host string) ([]net.IPAddr, error)
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
	host := ns.Hostname
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	if prot == "" {
		prot = "udp"
	}
	return fmt.Sprintf("%s/%s %s", addr, prot, host)
}

type resolverCacheItem struct {
	IPAddrs []net.IPAddr
	ts      int64
}

type resolver struct {
	Resolver *net.Resolver
	Servers  []NameServer
	Timeout  time.Duration
	TTL      time.Duration
	mCache   *sync.Map
}

// NewResolver create a new Resolver with the given name servers and resolution timeout.
func NewResolver(servers []NameServer, timeout, ttl time.Duration) Resolver {
	r := &resolver{
		Servers: servers,
		Timeout: timeout,
		TTL:     ttl,
		mCache:  &sync.Map{},
	}
	r.init()
	return r
}

func (r *resolver) init() {
	if r.Timeout <= 0 {
		r.Timeout = DefaultResolverTimeout
	}
	if r.TTL == 0 {
		r.TTL = DefaultResolverTTL
	}

	r.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (conn net.Conn, err error) {
			for _, ns := range r.Servers {
				conn, err = r.dial(ctx, ns)
				if err == nil {
					break
				}
				log.Logf("[resolver] %s : %s", ns, err)
			}
			return
		},
	}
}

func (r *resolver) dial(ctx context.Context, ns NameServer) (net.Conn, error) {
	var d net.Dialer

	addr := ns.Addr
	if !strings.Contains(addr, ":") {
		addr += ":53"
	}
	switch strings.ToLower(ns.Protocol) {
	case "tcp":
		return d.DialContext(ctx, "tcp", addr)
	case "tls":
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, err
		}
		cfg := &tls.Config{
			ServerName: ns.Hostname,
		}
		if cfg.ServerName == "" {
			cfg.InsecureSkipVerify = true
		}
		return tls.Client(conn, cfg), nil
	case "udp":
		fallthrough
	default:
		return d.DialContext(ctx, "udp", addr)
	}
}

func (r *resolver) Resolve(name string) (addrs []net.IPAddr, err error) {
	timeout := r.Timeout

	addrs = r.loadCache(name)
	if len(addrs) > 0 {
		if Debug {
			log.Logf("[resolver] cache hit: %s %v", name, addrs)
		}
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	addrs, err = r.Resolver.LookupIPAddr(ctx, name)
	r.storeCache(name, addrs)
	if len(addrs) > 0 && Debug {
		log.Logf("[resolver] %s %v", name, addrs)
	}
	return
}

func (r *resolver) loadCache(name string) []net.IPAddr {
	ttl := r.TTL
	if ttl < 0 {
		return nil
	}

	if v, ok := r.mCache.Load(name); ok {
		item, _ := v.(*resolverCacheItem)
		if item == nil || time.Since(time.Unix(item.ts, 0)) > ttl {
			return nil
		}
		return item.IPAddrs
	}

	return nil
}

func (r *resolver) storeCache(name string, addrs []net.IPAddr) {
	ttl := r.TTL
	if ttl < 0 || name == "" || len(addrs) == 0 {
		return
	}
	r.mCache.Store(name, &resolverCacheItem{
		IPAddrs: addrs,
		ts:      time.Now().Unix(),
	})
}

func (r *resolver) String() string {
	if r == nil {
		return ""
	}

	b := &bytes.Buffer{}
	fmt.Fprintf(b, "timeout %v\n", r.Timeout)
	fmt.Fprintf(b, "ttl %v\n", r.TTL)
	for i := range r.Servers {
		fmt.Fprintln(b, r.Servers[i])
	}
	return b.String()
}
