package gost

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ginuerzh/pht"
	"github.com/golang/glog"
	"github.com/lucas-clemente/quic-go/h2quic"
	"golang.org/x/net/http2"
)

// Proxy chain holds a list of proxy nodes
type ProxyChain struct {
	nodes          []ProxyNode
	lastNode       *ProxyNode
	http2NodeIndex int
	http2Enabled   bool
	http2Client    *http.Client
	kcpEnabled     bool
	kcpConfig      *KCPConfig
	kcpSession     *KCPSession
	kcpMutex       sync.Mutex
	phtClient      *pht.Client
	quicClient     *http.Client
}

func NewProxyChain(nodes ...ProxyNode) *ProxyChain {
	chain := &ProxyChain{nodes: nodes, http2NodeIndex: -1}
	return chain
}

func (c *ProxyChain) AddProxyNode(node ...ProxyNode) {
	c.nodes = append(c.nodes, node...)
}

func (c *ProxyChain) AddProxyNodeString(snode ...string) error {
	for _, sn := range snode {
		node, err := ParseProxyNode(sn)
		if err != nil {
			return err
		}
		c.AddProxyNode(node)
	}
	return nil
}

func (c *ProxyChain) Nodes() []ProxyNode {
	return c.nodes
}

func (c *ProxyChain) GetNode(index int) *ProxyNode {
	if index < len(c.nodes) {
		return &c.nodes[index]
	}
	return nil
}

func (c *ProxyChain) SetNode(index int, node ProxyNode) {
	if index < len(c.nodes) {
		c.nodes[index] = node
	}
}

// Init initialize the proxy chain.
// KCP will be enabled if the first proxy node is KCP proxy (transport == kcp).
// HTTP2 will be enabled when at least one HTTP2 proxy node (scheme == http2) is present.
//
// NOTE: Should be called immediately when proxy nodes are ready.
func (c *ProxyChain) Init() {
	length := len(c.nodes)
	if length == 0 {
		return
	}

	c.lastNode = &c.nodes[length-1]

	// HTTP2 restrict: HTTP2 will be enabled when at least one HTTP2 proxy node is present.
	for i, node := range c.nodes {
		if node.Transport == "http2" {
			glog.V(LINFO).Infoln("HTTP2 is enabled")
			cfg := &tls.Config{
				InsecureSkipVerify: node.insecureSkipVerify(),
				ServerName:         node.serverName,
			}

			caFile := node.caFile()

			if caFile != "" {
				cfg.RootCAs = x509.NewCertPool()

				data, err := ioutil.ReadFile(caFile)
				if err != nil {
					glog.Fatal(err)
				}

				if !cfg.RootCAs.AppendCertsFromPEM(data) {
					glog.Fatal(err)
				}
			}

			c.http2NodeIndex = i
			c.initHttp2Client(cfg, c.nodes[:i]...)
			break // shortest chain for HTTP2
		}
	}

	for i, node := range c.nodes {
		if (node.Transport == "kcp" || node.Transport == "pht" || node.Transport == "quic") && i > 0 {
			glog.Fatal("KCP/PHT/QUIC must be the first node in the proxy chain")
		}
	}

	if c.nodes[0].Transport == "kcp" {
		glog.V(LINFO).Infoln("KCP is enabled")
		c.kcpEnabled = true
		config, err := ParseKCPConfig(c.nodes[0].Get("c"))
		if err != nil {
			glog.V(LWARNING).Infoln("[kcp]", err)
		}
		if config == nil {
			config = DefaultKCPConfig
		}
		if c.nodes[0].Users != nil {
			config.Crypt = c.nodes[0].Users[0].Username()
			config.Key, _ = c.nodes[0].Users[0].Password()
		}
		c.kcpConfig = config
		go snmpLogger(config.SnmpLog, config.SnmpPeriod)
		go kcpSigHandler()

		return
	}

	if c.nodes[0].Transport == "quic" {
		glog.V(LINFO).Infoln("QUIC is enabled")
		c.quicClient = &http.Client{
			Transport: &h2quic.QuicRoundTripper{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: c.nodes[0].insecureSkipVerify(),
					ServerName:         c.nodes[0].serverName,
				},
			},
		}
	}

	if c.nodes[0].Transport == "pht" {
		glog.V(LINFO).Infoln("Pure HTTP mode is enabled")
		c.phtClient = pht.NewClient(c.nodes[0].Addr, c.nodes[0].Get("key"))
	}
}

func (c *ProxyChain) KCPEnabled() bool {
	return c.kcpEnabled
}

func (c *ProxyChain) Http2Enabled() bool {
	return c.http2Enabled
}

// Wrap a net.Conn into a client tls connection, performing any
// additional verification as needed.
//
// As of go 1.3, crypto/tls only supports either doing no certificate
// verification, or doing full verification including of the peer's
// DNS name. For consul, we want to validate that the certificate is
// signed by a known CA, but because consul doesn't use DNS names for
// node names, we don't verify the certificate DNS names. Since go 1.3
// no longer supports this mode of operation, we have to do it
// manually.
//
// This code is taken from consul:
// https://github.com/hashicorp/consul/blob/master/tlsutil/config.go
func wrapTLSClient(conn net.Conn, tlsConfig *tls.Config) (net.Conn, error) {
	var err error
	var tlsConn *tls.Conn

	tlsConn = tls.Client(conn, tlsConfig)

	// If crypto/tls is doing verification, there's no need to do our own.
	if tlsConfig.InsecureSkipVerify == false {
		return tlsConn, nil
	}

	// Similarly if we use host's CA, we can do full handshake
	if tlsConfig.RootCAs == nil {
		return tlsConn, nil
	}

	// Otherwise perform handshake, but don't verify the domain
	//
	// The following is lightly-modified from the doFullHandshake
	// method in https://golang.org/src/crypto/tls/handshake_client.go
	if err = tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	opts := x509.VerifyOptions{
		Roots:         tlsConfig.RootCAs,
		CurrentTime:   time.Now(),
		DNSName:       "",
		Intermediates: x509.NewCertPool(),
	}

	certs := tlsConn.ConnectionState().PeerCertificates
	for i, cert := range certs {
		if i == 0 {
			continue
		}
		opts.Intermediates.AddCert(cert)
	}

	_, err = certs[0].Verify(opts)
	if err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, err
}

func (c *ProxyChain) initHttp2Client(config *tls.Config, nodes ...ProxyNode) {
	if c.http2NodeIndex < 0 || c.http2NodeIndex >= len(c.nodes) {
		return
	}
	http2Node := c.nodes[c.http2NodeIndex]

	tr := http2.Transport{
		TLSClientConfig: config,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			// replace the default dialer with our proxy chain.
			conn, err := c.dialWithNodes(false, http2Node.Addr, nodes...)
			if err != nil {
				return conn, err
			}

			conn, err = wrapTLSClient(conn, cfg)
			if err != nil {
				return conn, err
			}

			// enable HTTP2 ping-pong
			pingIntvl, _ := strconv.Atoi(http2Node.Get("ping"))
			if pingIntvl > 0 {
				enablePing(conn, time.Duration(pingIntvl)*time.Second)
			}

			return conn, nil
		},
	}
	c.http2Client = &http.Client{Transport: &tr}
	c.http2Enabled = true

}

func enablePing(conn net.Conn, interval time.Duration) {
	if conn == nil || interval == 0 {
		return
	}

	glog.V(LINFO).Infoln("[http2] ping enabled, interval:", interval)
	go func() {
		t := time.NewTicker(interval)
		var framer *http2.Framer
		for {
			select {
			case <-t.C:
				if framer == nil {
					framer = http2.NewFramer(conn, conn)
				}

				var p [8]byte
				rand.Read(p[:])
				err := framer.WritePing(false, p)
				if err != nil {
					t.Stop()
					framer = nil
					glog.V(LWARNING).Infoln("[http2] ping:", err)
					return
				}
			}
		}
	}()
}

// Connect to addr through proxy chain
func (c *ProxyChain) Dial(addr string) (net.Conn, error) {
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	return c.dialWithNodes(true, addr, c.nodes...)
}

// GetConn initializes a proxy chain connection,
// if no proxy nodes on this chain, it will return error
func (c *ProxyChain) GetConn() (net.Conn, error) {
	nodes := c.nodes
	if len(nodes) == 0 {
		return nil, ErrEmptyChain
	}

	if c.Http2Enabled() {
		nodes = nodes[c.http2NodeIndex+1:]
		if len(nodes) == 0 {
			header := make(http.Header)
			header.Set("Proxy-Switch", "gost") // Flag header to indicate server to switch to HTTP2 transport mode
			conn, err := c.getHttp2Conn(header)
			if err != nil {
				return nil, err
			}
			http2Node := c.nodes[c.http2NodeIndex]
			if http2Node.Transport == "http2" {
				http2Node.Transport = "h2"
			}
			if http2Node.Protocol == "http2" {
				http2Node.Protocol = "socks5" // assume it as socks5 protocol, so we can do much more things.
			}
			pc := NewProxyConn(conn, http2Node)
			if err := pc.Handshake(); err != nil {
				conn.Close()
				return nil, err
			}
			return pc, nil
		}
	}
	return c.travelNodes(true, nodes...)
}

func (c *ProxyChain) dialWithNodes(withHttp2 bool, addr string, nodes ...ProxyNode) (conn net.Conn, err error) {
	if len(nodes) == 0 {
		return net.DialTimeout("tcp", addr, DialTimeout)
	}

	if withHttp2 && c.Http2Enabled() {
		nodes = nodes[c.http2NodeIndex+1:]
		if len(nodes) == 0 {
			return c.http2Connect(addr)
		}
	}

	if nodes[0].Transport == "quic" {
		glog.V(LINFO).Infoln("Dial with QUIC")
		return c.quicConnect(addr)
	}

	pc, err := c.travelNodes(withHttp2, nodes...)
	if err != nil {
		return
	}
	if err = pc.Connect(addr); err != nil {
		pc.Close()
		return
	}
	conn = pc
	return
}

func (c *ProxyChain) travelNodes(withHttp2 bool, nodes ...ProxyNode) (conn *ProxyConn, err error) {
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
			conn = nil
		}
	}()

	var cc net.Conn
	node := nodes[0]

	if withHttp2 && c.Http2Enabled() {
		cc, err = c.http2Connect(node.Addr)
	} else if node.Transport == "kcp" {
		cc, err = c.getKCPConn()
	} else if node.Transport == "pht" {
		cc, err = c.phtClient.Dial()
	} else {
		cc, err = net.DialTimeout("tcp", node.Addr, DialTimeout)
	}
	if err != nil {
		return
	}
	setKeepAlive(cc, KeepAliveTime)

	pc := NewProxyConn(cc, node)
	conn = pc
	if err = pc.Handshake(); err != nil {
		return
	}

	for _, node := range nodes[1:] {
		if err = conn.Connect(node.Addr); err != nil {
			return
		}
		pc := NewProxyConn(conn, node)
		conn = pc
		if err = pc.Handshake(); err != nil {
			return
		}
	}
	return
}

func (c *ProxyChain) initKCPSession() (err error) {
	c.kcpMutex.Lock()
	defer c.kcpMutex.Unlock()

	if c.kcpSession == nil || c.kcpSession.IsClosed() {
		glog.V(LINFO).Infoln("[kcp] new kcp session")
		c.kcpSession, err = DialKCP(c.nodes[0].Addr, c.kcpConfig)
	}
	return
}

func (c *ProxyChain) getKCPConn() (conn net.Conn, err error) {
	if !c.KCPEnabled() {
		return nil, errors.New("KCP is not enabled")
	}

	if err = c.initKCPSession(); err != nil {
		return nil, err
	}
	return c.kcpSession.GetConn()
}

// Initialize an HTTP2 transport if HTTP2 is enabled.
func (c *ProxyChain) getHttp2Conn(header http.Header) (net.Conn, error) {
	if !c.Http2Enabled() {
		return nil, errors.New("HTTP2 is not enabled")
	}
	http2Node := c.nodes[c.http2NodeIndex]
	pr, pw := io.Pipe()

	if header == nil {
		header = make(http.Header)
	}

	req := http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: http2Node.Addr},
		Header:        header,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Body:          pr,
		Host:          http2Node.Addr,
		ContentLength: -1,
	}
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(&req, false)
		glog.Infoln(string(dump))
	}
	resp, err := c.http2Client.Do(&req)
	if err != nil {
		return nil, err
	}
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpResponse(resp, false)
		glog.Infoln(string(dump))
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errors.New(resp.Status)
	}
	conn := &http2Conn{r: resp.Body, w: pw}
	conn.remoteAddr, _ = net.ResolveTCPAddr("tcp", http2Node.Addr)
	return conn, nil
}

// Use HTTP2 as transport to connect target addr.
//
// BUG: SOCKS5 is ignored, only HTTP supported
func (c *ProxyChain) http2Connect(addr string) (net.Conn, error) {
	if !c.Http2Enabled() {
		return nil, errors.New("HTTP2 is not enabled")
	}
	http2Node := c.nodes[c.http2NodeIndex]

	header := make(http.Header)
	header.Set("Gost-Target", addr) // Flag header to indicate the address that server connected to
	if http2Node.Users != nil {
		header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(http2Node.Users[0].String())))
	}
	return c.getHttp2Conn(header)
}

func (c *ProxyChain) quicConnect(addr string) (net.Conn, error) {
	quicNode := c.nodes[0]
	header := make(http.Header)
	header.Set("Gost-Target", addr) // Flag header to indicate the address that server connected to
	if quicNode.Users != nil {
		header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(quicNode.Users[0].String())))
	}
	return c.getQuicConn(header)
}

func (c *ProxyChain) getQuicConn(header http.Header) (net.Conn, error) {
	quicNode := c.nodes[0]
	pr, pw := io.Pipe()

	if header == nil {
		header = make(http.Header)
	}

	/*
		req := http.Request{
			Method:        http.MethodGet,
			URL:           &url.URL{Scheme: "https", Host: quicNode.Addr},
			Header:        header,
			Proto:         "HTTP/2.0",
			ProtoMajor:    2,
			ProtoMinor:    0,
			Body:          pr,
			Host:          quicNode.Addr,
			ContentLength: -1,
		}
	*/
	req, err := http.NewRequest(http.MethodPost, "https://"+quicNode.Addr, pr)
	if err != nil {
		return nil, err
	}
	req.ContentLength = -1
	req.Header = header

	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpRequest(req, false)
		glog.Infoln(string(dump))
	}
	resp, err := c.quicClient.Do(req)
	if err != nil {
		return nil, err
	}
	if glog.V(LDEBUG) {
		dump, _ := httputil.DumpResponse(resp, false)
		glog.Infoln(string(dump))
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errors.New(resp.Status)
	}
	conn := &http2Conn{r: resp.Body, w: pw}
	conn.remoteAddr, _ = net.ResolveUDPAddr("udp", quicNode.Addr)
	return conn, nil
}

type Chain struct {
	nodes []Node
}

func (c *Chain) Dial(addr string) (net.Conn, error) {
	if len(c.nodes) == 0 {
		return net.Dial("tcp", addr)
	}

	nodes := c.nodes
	conn, err := nodes[0].Client().Connect()
	if err != nil {
		return nil, err
	}

	for i, node := range nodes {
		if i == len(nodes)-1 {
			break
		}

		cn, err := node.Client().Dial(conn, nodes[i+1].Options().BaseOptions().Addr)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = cn
	}

	cn, err := nodes[len(nodes)-1].Client().Dial(conn, addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cn, nil
}
