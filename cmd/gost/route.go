package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/ginuerzh/gost"
	"github.com/go-log/log"
)

type stringList []string

func (l *stringList) String() string {
	return fmt.Sprintf("%s", *l)
}
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

type route struct {
	ServeNodes stringList
	ChainNodes stringList
	Retries    int
}

func (r *route) parseChain() (*gost.Chain, error) {
	chain := gost.NewChain()
	chain.Retries = r.Retries
	gid := 1 // group ID

	for _, ns := range r.ChainNodes {
		ngroup := gost.NewNodeGroup()
		ngroup.ID = gid
		gid++

		// parse the base nodes
		nodes, err := parseChainNode(ns)
		if err != nil {
			return nil, err
		}

		nid := 1 // node ID
		for i := range nodes {
			nodes[i].ID = nid
			nid++
		}
		ngroup.AddNode(nodes...)

		ngroup.SetSelector(nil,
			gost.WithFilter(
				&gost.FailFilter{
					MaxFails:    nodes[0].GetInt("max_fails"),
					FailTimeout: nodes[0].GetDuration("fail_timeout"),
				},
				&gost.InvalidFilter{},
			),
			gost.WithStrategy(gost.NewStrategy(nodes[0].Get("strategy"))),
		)

		if cfg := nodes[0].Get("peer"); cfg != "" {
			f, err := os.Open(cfg)
			if err != nil {
				return nil, err
			}

			peerCfg := newPeerConfig()
			peerCfg.group = ngroup
			peerCfg.baseNodes = nodes
			peerCfg.Reload(f)
			f.Close()

			go gost.PeriodReload(peerCfg, cfg)
		}

		chain.AddNodeGroup(ngroup)
	}

	return chain, nil
}

func parseChainNode(ns string) (nodes []gost.Node, err error) {
	node, err := gost.ParseNode(ns)
	if err != nil {
		return
	}

	if auth := node.Get("auth"); auth != "" && node.User == nil {
		c, err := base64.StdEncoding.DecodeString(auth)
		if err != nil {
			return nil, err
		}
		cs := string(c)
		s := strings.IndexByte(cs, ':')
		if s < 0 {
			node.User = url.User(cs)
		} else {
			node.User = url.UserPassword(cs[:s], cs[s+1:])
		}
	}
	if node.User == nil {
		users, err := parseUsers(node.Get("secrets"))
		if err != nil {
			return nil, err
		}
		if len(users) > 0 {
			node.User = users[0]
		}
	}

	serverName, sport, _ := net.SplitHostPort(node.Addr)
	if serverName == "" {
		serverName = "localhost" // default server name
	}

	rootCAs, err := loadCA(node.Get("ca"))
	if err != nil {
		return
	}
	tlsCfg := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: !node.GetBool("secure"),
		RootCAs:            rootCAs,
	}
	wsOpts := &gost.WSOptions{}
	wsOpts.EnableCompression = node.GetBool("compression")
	wsOpts.ReadBufferSize = node.GetInt("rbuf")
	wsOpts.WriteBufferSize = node.GetInt("wbuf")
	wsOpts.UserAgent = node.Get("agent")
	wsOpts.Path = node.Get("path")

	timeout := node.GetDuration("timeout")

	var tr gost.Transporter
	switch node.Transport {
	case "tls":
		tr = gost.TLSTransporter()
	case "mtls":
		tr = gost.MTLSTransporter()
	case "ws":
		tr = gost.WSTransporter(wsOpts)
	case "mws":
		tr = gost.MWSTransporter(wsOpts)
	case "wss":
		tr = gost.WSSTransporter(wsOpts)
	case "mwss":
		tr = gost.MWSSTransporter(wsOpts)
	case "kcp":
		config, err := parseKCPConfig(node.Get("c"))
		if err != nil {
			return nil, err
		}
		if config == nil {
			conf := gost.DefaultKCPConfig
			if node.GetBool("tcp") {
				conf.TCP = true
			}
			config = &conf
		}
		tr = gost.KCPTransporter(config)
	case "ssh":
		if node.Protocol == "direct" || node.Protocol == "remote" {
			tr = gost.SSHForwardTransporter()
		} else {
			tr = gost.SSHTunnelTransporter()
		}
	case "quic":
		config := &gost.QUICConfig{
			TLSConfig:   tlsCfg,
			KeepAlive:   node.GetBool("keepalive"),
			Timeout:     timeout,
			IdleTimeout: node.GetDuration("idle"),
		}

		if cipher := node.Get("cipher"); cipher != "" {
			sum := sha256.Sum256([]byte(cipher))
			config.Key = sum[:]
		}

		tr = gost.QUICTransporter(config)
	case "http2":
		tr = gost.HTTP2Transporter(tlsCfg)
	case "h2":
		tr = gost.H2Transporter(tlsCfg, node.Get("path"))
	case "h2c":
		tr = gost.H2CTransporter(node.Get("path"))
	case "obfs4":
		tr = gost.Obfs4Transporter()
	case "ohttp":
		tr = gost.ObfsHTTPTransporter()
	case "otls":
		tr = gost.ObfsTLSTransporter()
	case "ftcp":
		tr = gost.FakeTCPTransporter()
	case "udp":
		tr = gost.UDPTransporter()
	default:
		tr = gost.TCPTransporter()
	}

	var connector gost.Connector
	switch node.Protocol {
	case "http2":
		connector = gost.HTTP2Connector(node.User)
	case "socks", "socks5":
		connector = gost.SOCKS5Connector(node.User)
	case "socks4":
		connector = gost.SOCKS4Connector()
	case "socks4a":
		connector = gost.SOCKS4AConnector()
	case "ss":
		connector = gost.ShadowConnector(node.User)
	case "ssu":
		connector = gost.ShadowUDPConnector(node.User)
	case "direct":
		connector = gost.SSHDirectForwardConnector()
	case "remote":
		connector = gost.SSHRemoteForwardConnector()
	case "forward":
		connector = gost.ForwardConnector()
	case "sni":
		connector = gost.SNIConnector(node.Get("host"))
	case "http":
		connector = gost.HTTPConnector(node.User)
	case "relay":
		connector = gost.RelayConnector(node.User)
	default:
		connector = gost.AutoConnector(node.User)
	}

	node.DialOptions = append(node.DialOptions,
		gost.TimeoutDialOption(timeout),
	)

	node.ConnectOptions = []gost.ConnectOption{
		gost.UserAgentConnectOption(node.Get("agent")),
		gost.NoTLSConnectOption(node.GetBool("notls")),
		gost.NoDelayConnectOption(node.GetBool("nodelay")),
	}

	host := node.Get("host")
	if host == "" {
		host = node.Host
	}
	handshakeOptions := []gost.HandshakeOption{
		gost.AddrHandshakeOption(node.Addr),
		gost.HostHandshakeOption(host),
		gost.UserHandshakeOption(node.User),
		gost.TLSConfigHandshakeOption(tlsCfg),
		gost.IntervalHandshakeOption(node.GetDuration("ping")),
		gost.TimeoutHandshakeOption(timeout),
		gost.RetryHandshakeOption(node.GetInt("retry")),
	}
	node.Client = &gost.Client{
		Connector:   connector,
		Transporter: tr,
	}

	node.Bypass = parseBypass(node.Get("bypass"))

	ips := parseIP(node.Get("ip"), sport)
	for _, ip := range ips {
		nd := node.Clone()
		nd.Addr = ip
		// override the default node address
		nd.HandshakeOptions = append(handshakeOptions, gost.AddrHandshakeOption(ip))
		// One node per IP
		nodes = append(nodes, nd)
	}
	if len(ips) == 0 {
		node.HandshakeOptions = handshakeOptions
		nodes = []gost.Node{node}
	}

	if node.Transport == "obfs4" {
		for i := range nodes {
			if err := gost.Obfs4Init(nodes[i], false); err != nil {
				return nil, err
			}
		}
	}

	return
}

func (r *route) GenRouters() ([]router, error) {
	chain, err := r.parseChain()
	if err != nil {
		return nil, err
	}

	var rts []router

	for _, ns := range r.ServeNodes {
		node, err := gost.ParseNode(ns)
		if err != nil {
			return nil, err
		}

		if auth := node.Get("auth"); auth != "" && node.User == nil {
			c, err := base64.StdEncoding.DecodeString(auth)
			if err != nil {
				return nil, err
			}
			cs := string(c)
			s := strings.IndexByte(cs, ':')
			if s < 0 {
				node.User = url.User(cs)
			} else {
				node.User = url.UserPassword(cs[:s], cs[s+1:])
			}
		}
		authenticator, err := parseAuthenticator(node.Get("secrets"))
		if err != nil {
			return nil, err
		}
		if authenticator == nil && node.User != nil {
			kvs := make(map[string]string)
			kvs[node.User.Username()], _ = node.User.Password()
			authenticator = gost.NewLocalAuthenticator(kvs)
		}
		if node.User == nil {
			if users, _ := parseUsers(node.Get("secrets")); len(users) > 0 {
				node.User = users[0]
			}
		}
		certFile, keyFile := node.Get("cert"), node.Get("key")
		tlsCfg, err := tlsConfig(certFile, keyFile)
		if err != nil && certFile != "" && keyFile != "" {
			return nil, err
		}

		wsOpts := &gost.WSOptions{}
		wsOpts.EnableCompression = node.GetBool("compression")
		wsOpts.ReadBufferSize = node.GetInt("rbuf")
		wsOpts.WriteBufferSize = node.GetInt("wbuf")
		wsOpts.Path = node.Get("path")

		ttl := node.GetDuration("ttl")
		timeout := node.GetDuration("timeout")

		tunRoutes := parseIPRoutes(node.Get("route"))
		gw := net.ParseIP(node.Get("gw")) // default gateway
		for i := range tunRoutes {
			if tunRoutes[i].Gateway == nil {
				tunRoutes[i].Gateway = gw
			}
		}

		var ln gost.Listener
		switch node.Transport {
		case "tls":
			ln, err = gost.TLSListener(node.Addr, tlsCfg)
		case "mtls":
			ln, err = gost.MTLSListener(node.Addr, tlsCfg)
		case "ws":
			ln, err = gost.WSListener(node.Addr, wsOpts)
		case "mws":
			ln, err = gost.MWSListener(node.Addr, wsOpts)
		case "wss":
			ln, err = gost.WSSListener(node.Addr, tlsCfg, wsOpts)
		case "mwss":
			ln, err = gost.MWSSListener(node.Addr, tlsCfg, wsOpts)
		case "kcp":
			config, er := parseKCPConfig(node.Get("c"))
			if er != nil {
				return nil, er
			}
			if config == nil {
				conf := gost.DefaultKCPConfig
				if node.GetBool("tcp") {
					conf.TCP = true
				}
				config = &conf
			}
			ln, err = gost.KCPListener(node.Addr, config)
		case "ssh":
			config := &gost.SSHConfig{
				Authenticator: authenticator,
				TLSConfig:     tlsCfg,
			}
			if node.Protocol == "forward" {
				ln, err = gost.TCPListener(node.Addr)
			} else {
				ln, err = gost.SSHTunnelListener(node.Addr, config)
			}
		case "quic":
			config := &gost.QUICConfig{
				TLSConfig:   tlsCfg,
				KeepAlive:   node.GetBool("keepalive"),
				Timeout:     timeout,
				IdleTimeout: node.GetDuration("idle"),
			}
			if cipher := node.Get("cipher"); cipher != "" {
				sum := sha256.Sum256([]byte(cipher))
				config.Key = sum[:]
			}

			ln, err = gost.QUICListener(node.Addr, config)
		case "http2":
			ln, err = gost.HTTP2Listener(node.Addr, tlsCfg)
		case "h2":
			ln, err = gost.H2Listener(node.Addr, tlsCfg, node.Get("path"))
		case "h2c":
			ln, err = gost.H2CListener(node.Addr, node.Get("path"))
		case "tcp":
			// Directly use SSH port forwarding if the last chain node is forward+ssh
			if chain.LastNode().Protocol == "forward" && chain.LastNode().Transport == "ssh" {
				chain.Nodes()[len(chain.Nodes())-1].Client.Connector = gost.SSHDirectForwardConnector()
				chain.Nodes()[len(chain.Nodes())-1].Client.Transporter = gost.SSHForwardTransporter()
			}
			ln, err = gost.TCPListener(node.Addr)
		case "udp":
			ln, err = gost.UDPListener(node.Addr, &gost.UDPListenConfig{
				TTL:       ttl,
				Backlog:   node.GetInt("backlog"),
				QueueSize: node.GetInt("queue"),
			})
		case "rtcp":
			// Directly use SSH port forwarding if the last chain node is forward+ssh
			if chain.LastNode().Protocol == "forward" && chain.LastNode().Transport == "ssh" {
				chain.Nodes()[len(chain.Nodes())-1].Client.Connector = gost.SSHRemoteForwardConnector()
				chain.Nodes()[len(chain.Nodes())-1].Client.Transporter = gost.SSHForwardTransporter()
			}
			ln, err = gost.TCPRemoteForwardListener(node.Addr, chain)
		case "rudp":
			ln, err = gost.UDPRemoteForwardListener(node.Addr,
				chain,
				&gost.UDPListenConfig{
					TTL:       ttl,
					Backlog:   node.GetInt("backlog"),
					QueueSize: node.GetInt("queue"),
				})
		case "obfs4":
			if err = gost.Obfs4Init(node, true); err != nil {
				return nil, err
			}
			ln, err = gost.Obfs4Listener(node.Addr)
		case "ohttp":
			ln, err = gost.ObfsHTTPListener(node.Addr)
		case "otls":
			ln, err = gost.ObfsTLSListener(node.Addr)
		case "tun":
			cfg := gost.TunConfig{
				Name:    node.Get("name"),
				Addr:    node.Get("net"),
				Peer:    node.Get("peer"),
				MTU:     node.GetInt("mtu"),
				Routes:  tunRoutes,
				Gateway: node.Get("gw"),
			}
			ln, err = gost.TunListener(cfg)
		case "tap":
			cfg := gost.TapConfig{
				Name:    node.Get("name"),
				Addr:    node.Get("net"),
				MTU:     node.GetInt("mtu"),
				Routes:  strings.Split(node.Get("route"), ","),
				Gateway: node.Get("gw"),
			}
			ln, err = gost.TapListener(cfg)
		case "ftcp":
			ln, err = gost.FakeTCPListener(
				node.Addr,
				&gost.FakeTCPListenConfig{
					TTL:       ttl,
					Backlog:   node.GetInt("backlog"),
					QueueSize: node.GetInt("queue"),
				},
			)
		case "dns":
			ln, err = gost.DNSListener(
				node.Addr,
				&gost.DNSOptions{
					Mode:      node.Get("mode"),
					TLSConfig: tlsCfg,
				},
			)
		case "redu", "redirectu":
			ln, err = gost.UDPRedirectListener(node.Addr, &gost.UDPListenConfig{
				TTL:       ttl,
				Backlog:   node.GetInt("backlog"),
				QueueSize: node.GetInt("queue"),
			})
		default:
			ln, err = gost.TCPListener(node.Addr)
		}
		if err != nil {
			return nil, err
		}

		var handler gost.Handler
		switch node.Protocol {
		case "http2":
			handler = gost.HTTP2Handler()
		case "socks", "socks5":
			handler = gost.SOCKS5Handler()
		case "socks4", "socks4a":
			handler = gost.SOCKS4Handler()
		case "ss":
			handler = gost.ShadowHandler()
		case "http":
			handler = gost.HTTPHandler()
		case "tcp":
			handler = gost.TCPDirectForwardHandler(node.Remote)
		case "rtcp":
			handler = gost.TCPRemoteForwardHandler(node.Remote)
		case "udp":
			handler = gost.UDPDirectForwardHandler(node.Remote)
		case "rudp":
			handler = gost.UDPRemoteForwardHandler(node.Remote)
		case "forward":
			handler = gost.SSHForwardHandler()
		case "red", "redirect":
			handler = gost.TCPRedirectHandler()
		case "redu", "redirectu":
			handler = gost.UDPRedirectHandler()
		case "ssu":
			handler = gost.ShadowUDPHandler()
		case "sni":
			handler = gost.SNIHandler()
		case "tun":
			handler = gost.TunHandler()
		case "tap":
			handler = gost.TapHandler()
		case "dns":
			handler = gost.DNSHandler(node.Remote)
		case "relay":
			handler = gost.RelayHandler(node.Remote)
		default:
			// start from 2.5, if remote is not empty, then we assume that it is a forward tunnel.
			if node.Remote != "" {
				handler = gost.TCPDirectForwardHandler(node.Remote)
			} else {
				handler = gost.AutoHandler()
			}
		}

		var whitelist, blacklist *gost.Permissions
		if node.Values.Get("whitelist") != "" {
			if whitelist, err = gost.ParsePermissions(node.Get("whitelist")); err != nil {
				return nil, err
			}
		}
		if node.Values.Get("blacklist") != "" {
			if blacklist, err = gost.ParsePermissions(node.Get("blacklist")); err != nil {
				return nil, err
			}
		}

		node.Bypass = parseBypass(node.Get("bypass"))
		hosts := parseHosts(node.Get("hosts"))
		ips := parseIP(node.Get("ip"), "")

		resolver := parseResolver(node.Get("dns"))
		if resolver != nil {
			resolver.Init(
				gost.ChainResolverOption(chain),
				gost.TimeoutResolverOption(timeout),
				gost.TTLResolverOption(ttl),
				gost.PreferResolverOption(node.Get("prefer")),
				gost.SrcIPResolverOption(net.ParseIP(node.Get("ip"))),
			)
		}

		handler.Init(
			gost.AddrHandlerOption(ln.Addr().String()),
			gost.ChainHandlerOption(chain),
			gost.UsersHandlerOption(node.User),
			gost.AuthenticatorHandlerOption(authenticator),
			gost.TLSConfigHandlerOption(tlsCfg),
			gost.WhitelistHandlerOption(whitelist),
			gost.BlacklistHandlerOption(blacklist),
			gost.StrategyHandlerOption(gost.NewStrategy(node.Get("strategy"))),
			gost.MaxFailsHandlerOption(node.GetInt("max_fails")),
			gost.FailTimeoutHandlerOption(node.GetDuration("fail_timeout")),
			gost.BypassHandlerOption(node.Bypass),
			gost.ResolverHandlerOption(resolver),
			gost.HostsHandlerOption(hosts),
			gost.RetryHandlerOption(node.GetInt("retry")), // override the global retry option.
			gost.TimeoutHandlerOption(timeout),
			gost.ProbeResistHandlerOption(node.Get("probe_resist")),
			gost.KnockingHandlerOption(node.Get("knock")),
			gost.NodeHandlerOption(node),
			gost.IPsHandlerOption(ips),
			gost.TCPModeHandlerOption(node.GetBool("tcp")),
			gost.IPRoutesHandlerOption(tunRoutes...),
		)

		rt := router{
			node:     node,
			server:   &gost.Server{Listener: ln},
			handler:  handler,
			chain:    chain,
			resolver: resolver,
			hosts:    hosts,
		}
		rts = append(rts, rt)
	}

	return rts, nil
}

type router struct {
	node     gost.Node
	server   *gost.Server
	handler  gost.Handler
	chain    *gost.Chain
	resolver gost.Resolver
	hosts    *gost.Hosts
}

func (r *router) Serve() error {
	log.Logf("%s on %s", r.node.String(), r.server.Addr())
	return r.server.Serve(r.handler)
}

func (r *router) Close() error {
	if r == nil || r.server == nil {
		return nil
	}
	return r.server.Close()
}
