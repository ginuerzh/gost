package gost

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// Proxy chain holds a list of proxy nodes
type ProxyChain struct {
	nodes          []ProxyNode
	lastNode       *ProxyNode
	http2NodeIndex int
	http2Enabled   bool
	http2Client    *http.Client
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

// TryEnableHttp2 initialize HTTP2 if available.
// HTTP2 will be enabled when at least one HTTP2 proxy node (scheme == http2) is present.
//
// NOTE: Should be called immediately when proxy nodes are ready, HTTP2 will not be enabled if this function not be called.
func (c *ProxyChain) TryEnableHttp2() {
	length := len(c.nodes)
	if length == 0 {
		return
	}

	c.lastNode = &c.nodes[length-1]

	// HTTP2 restrict: HTTP2 will be enabled when at least one HTTP2 proxy node is present.
	for i, node := range c.nodes {
		if node.Transport == "http2" {
			glog.V(LINFO).Infoln("HTTP2 enabled")
			cfg := &tls.Config{
				InsecureSkipVerify: node.insecureSkipVerify(),
				ServerName:         node.serverName,
			}
			c.initHttp2Client(node.Addr, cfg, c.nodes[:i]...)
			c.http2NodeIndex = i
			break // shortest chain for HTTP2
		}
	}
}

func (c *ProxyChain) Http2Enabled() bool {
	return c.http2Enabled
}

func (c *ProxyChain) initHttp2Client(addr string, config *tls.Config, nodes ...ProxyNode) {
	tr := http2.Transport{
		TLSClientConfig: config,
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			// replace the default dialer with our proxy chain.
			conn, err := c.dialWithNodes(addr, nodes...)
			if err != nil {
				return conn, err
			}
			return tls.Client(conn, cfg), nil
		},
	}
	c.http2Client = &http.Client{Transport: &tr}
	c.http2Enabled = true

}

// Connect to addr through proxy chain
func (c *ProxyChain) Dial(addr string) (net.Conn, error) {
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	return c.dialWithNodes(addr, c.nodes...)
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
			if http2Node.Protocol == "" {
				http2Node.Protocol = "socks5" // assume it as socks5 protocol
			}
			pc := NewProxyConn(conn, http2Node)
			if err := pc.Handshake(); err != nil {
				conn.Close()
				return nil, err
			}
			return pc, nil
		}
	}
	return c.travelNodes(nodes...)
}

func (c *ProxyChain) dialWithNodes(addr string, nodes ...ProxyNode) (conn net.Conn, err error) {
	if len(nodes) == 0 {
		return net.DialTimeout("tcp", addr, DialTimeout)
	}

	if c.Http2Enabled() {
		nodes = nodes[c.http2NodeIndex+1:]
		if len(nodes) == 0 {
			return c.http2Connect(addr)
		}
	}
	pc, err := c.travelNodes(nodes...)
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

func (c *ProxyChain) travelNodes(nodes ...ProxyNode) (conn *ProxyConn, err error) {
	defer func() {
		if err != nil && conn != nil {
			conn.Close()
			conn = nil
		}
	}()

	var cc net.Conn
	node := nodes[0]

	if c.Http2Enabled() {
		cc, err = c.http2Connect(node.Addr)
	} else {
		cc, err = net.DialTimeout("tcp", node.Addr, DialTimeout)
	}
	if err != nil {
		return
	}
	setKeepAlive(cc, KeepAliveTime)

	pc := NewProxyConn(cc, node)
	if err = pc.Handshake(); err != nil {
		return
	}
	conn = pc
	for _, node := range nodes[1:] {
		if err = conn.Connect(node.Addr); err != nil {
			return
		}
		pc := NewProxyConn(conn, node)
		if err = pc.Handshake(); err != nil {
			return
		}
		conn = pc
	}
	return
}

// Initialize an HTTP2 transport if HTTP2 is enabled.
func (c *ProxyChain) getHttp2Conn(header http.Header) (net.Conn, error) {
	if !c.Http2Enabled() {
		return nil, errors.New("HTTP2 not enabled")
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
		Body:          ioutil.NopCloser(pr),
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
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, errors.New(resp.Status)
	}
	conn := &http2Conn{r: resp.Body, w: pw}
	conn.remoteAddr, _ = net.ResolveTCPAddr("tcp", http2Node.Addr)
	return conn, nil
}

// Use HTTP2 as transport to connect target addr
func (c *ProxyChain) http2Connect(addr string) (net.Conn, error) {
	if !c.Http2Enabled() {
		return nil, errors.New("HTTP2 not enabled")
	}
	http2Node := c.nodes[c.http2NodeIndex]

	header := make(http.Header)
	header.Set("Gost-Target", addr) // Flag header to indicate the address that server connected to
	if http2Node.User != nil {
		header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(http2Node.User.String())))
	}
	return c.getHttp2Conn(header)
}
