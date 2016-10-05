package gost

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Proxy node represent a proxy
type ProxyNode struct {
	Addr       string        // [host]:port
	Protocol   string        // protocol: http/socks5/ss
	Transport  string        // transport: ws/wss/tls/http2/tcp/udp/rtcp/rudp
	Remote     string        // remote address, used by tcp/udp port forwarding
	User       *url.Userinfo // authentication for proxy
	values     url.Values
	serverName string
	conn       net.Conn
}

// The proxy node string pattern is [scheme://][user:pass@host]:port.
//
// Scheme can be devided into two parts by character '+', such as: http+tls.
func ParseProxyNode(s string) (node ProxyNode, err error) {
	if !strings.Contains(s, "://") {
		s = "gost://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	node = ProxyNode{
		Addr:       u.Host,
		User:       u.User,
		values:     u.Query(),
		serverName: u.Host,
	}

	if strings.Contains(u.Host, ":") {
		node.serverName, _, _ = net.SplitHostPort(u.Host)
		if node.serverName == "" {
			node.serverName = "localhost" // default server name
		}
	}

	schemes := strings.Split(u.Scheme, "+")
	if len(schemes) == 1 {
		node.Protocol = schemes[0]
		node.Transport = schemes[0]
	}
	if len(schemes) == 2 {
		node.Protocol = schemes[0]
		node.Transport = schemes[1]
	}

	switch node.Transport {
	case "ws", "wss", "tls", "http2":
	case "https":
		node.Protocol = "http"
		node.Transport = "tls"
	case "tcp", "udp": // started from v2.1, tcp and udp are for local port forwarding
		node.Remote = strings.Trim(u.EscapedPath(), "/")
	case "rtcp", "rudp": // started from v2.1, rtcp and rudp are for remote port forwarding
		node.Remote = strings.Trim(u.EscapedPath(), "/")
	default:
		node.Transport = ""
	}

	switch node.Protocol {
	case "http", "socks", "socks5", "ss":
	default:
		node.Protocol = ""
	}

	return
}

// Get get node parameter by key
func (node *ProxyNode) Get(key string) string {
	return node.values.Get(key)
}

func (node *ProxyNode) getBool(key string) bool {
	s := node.Get(key)
	if b, _ := strconv.ParseBool(s); b {
		return b
	}
	n, _ := strconv.Atoi(s)
	return n > 0
}

func (node *ProxyNode) Set(key, value string) {
	node.values.Set(key, value)
}

func (node *ProxyNode) insecureSkipVerify() bool {
	return !node.getBool("secure")
}

func (node *ProxyNode) certFile() string {
	if cert := node.Get("cert"); cert != "" {
		return cert
	}
	return DefaultCertFile
}

func (node *ProxyNode) keyFile() string {
	if key := node.Get("key"); key != "" {
		return key
	}
	return DefaultKeyFile
}
