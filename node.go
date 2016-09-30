package gost

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Proxy node represent a proxy
type ProxyNode struct {
	Addr       string        // host:port
	Protocol   string        // protocol: http/http2/socks5/ss
	Transport  string        // transport: ws/wss/tls/tcp/udp/rtcp/rudp
	Remote     string        // remote address, used by tcp/udp port forwarding
	User       *url.Userinfo // authentication for proxy
	values     url.Values
	serverName string
	conn       net.Conn
}

// the format is [scheme://][user:pass@host]:port
func ParseProxyNode(s string) (node *ProxyNode, err error) {
	if !strings.Contains(s, "://") {
		s = "gost://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	node = &ProxyNode{
		Addr:       u.Host,
		User:       u.User,
		values:     u.Query(),
		serverName: u.Host,
	}

	if strings.Contains(u.Host, ":") {
		node.serverName, _, _ = net.SplitHostPort(u.Host)
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
	case "ws", "wss", "tls":
	case "https":
		node.Protocol = "http"
		node.Transport = "tls"
	case "http2":
		node.Protocol = "http2"
	case "tcp", "udp": // started from v2.1, tcp and udp are for local port forwarding
		node.Remote = strings.Trim(u.EscapedPath(), "/")
	case "rtcp", "rudp": // started from v2.1, rtcp and rudp are for remote port forwarding
		node.Remote = strings.Trim(u.EscapedPath(), "/")
	default:
		node.Transport = ""
	}

	switch node.Protocol {
	case "http", "http2", "socks", "socks5", "ss":
	default:
		node.Protocol = ""
	}

	return
}

func (node *ProxyNode) insecureSkipVerify() bool {
	s := node.values.Get("secure")
	if secure, _ := strconv.ParseBool(s); secure {
		return !secure
	}
	if n, _ := strconv.Atoi(s); n > 0 {
		return false
	}
	return true
}

func (node *ProxyNode) certFile() string {
	if cert := node.values.Get("cert"); cert != "" {
		return cert
	}
	return DefaultCertFile
}

func (node *ProxyNode) keyFile() string {
	if key := node.values.Get("key"); key != "" {
		return key
	}
	return DefaultKeyFile
}
