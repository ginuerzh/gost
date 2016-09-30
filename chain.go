package gost

import (
	"crypto/tls"
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

// Initialize proxy nodes, mainly check for http2 feature.
// Should be called immediately when proxy nodes are ready.
//
// NOTE: http2 will not be enabled if not called.
func (c *ProxyChain) Init() {
	length := len(c.nodes)
	if length == 0 {
		return
	}

	c.lastNode = &c.nodes[length-1]

	// http2 restrict: http2 will be enabled when at least one http2 proxy node present
	for i, node := range c.nodes {
		if node.Transport == "http2" {
			glog.V(LINFO).Infoln("http2 enabled")
			cfg := &tls.Config{
				InsecureSkipVerify: node.insecureSkipVerify(),
				ServerName:         node.serverName,
			}
			c.initHttp2Client(node.Addr, cfg, c.nodes[:i]...)
			c.http2NodeIndex = i
			break // shortest chain for http2
		}
	}
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

func (c *ProxyChain) Http2Enabled() bool {
	return c.http2Enabled
}

// Connect to addr through proxy chain
func (c *ProxyChain) Dial(addr string) (net.Conn, error) {
	if !strings.Contains(addr, ":") {
		addr += ":80"
	}
	return c.dialWithNodes(addr, c.nodes...)
}

func (c *ProxyChain) dialWithNodes(addr string, nodes ...ProxyNode) (conn net.Conn, err error) {
	if len(nodes) == 0 {
		return net.DialTimeout("tcp", addr, DialTimeout)
	}

	var pc *ProxyConn

	if c.Http2Enabled() {
		nodes = nodes[c.http2NodeIndex+1:]
		if len(nodes) == 0 {
			return c.http2Connect("http", addr)
		}
	}
	pc, err = c.travelNodes(nodes...)
	if err != nil {
		return
	}
	if err = pc.Connect(addr); err != nil {
		pc.Close()
		return
	}

	return pc, nil
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
		cc, err = c.http2Connect("http", node.Addr)
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

func (c *ProxyChain) http2Connect(protocol, addr string) (net.Conn, error) {
	if !c.Http2Enabled() {
		return nil, errors.New("http2 not enabled")
	}
	http2Node := c.nodes[c.http2NodeIndex]

	pr, pw := io.Pipe()
	req := http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "https", Host: http2Node.Addr},
		Header:        make(http.Header),
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Body:          ioutil.NopCloser(pr),
		Host:          http2Node.Addr,
		ContentLength: -1,
	}
	req.Header.Set("gost-target", addr)
	if protocol != "" {
		req.Header.Set("gost-protocol", protocol)
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
	conn := &Http2ClientConn{r: resp.Body, w: pw}
	conn.remoteAddr, _ = net.ResolveTCPAddr("tcp", addr)
	return conn, nil
}
