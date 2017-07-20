package gost

import (
	"bufio"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/golang/glog"
)

// Proxy node represent a proxy
type ProxyNode struct {
	Addr       string          // [host]:port
	Protocol   string          // protocol: http/socks5/ss
	Transport  string          // transport: ws/wss/tls/http2/tcp/udp/rtcp/rudp
	Remote     string          // remote address, used by tcp/udp port forwarding
	Users      []*url.Userinfo // authentication for proxy
	Whitelist  *Permissions
	Blacklist  *Permissions
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

	query := u.Query()

	node = ProxyNode{
		Addr:       u.Host,
		values:     query,
		serverName: u.Host,
	}

	if query.Get("whitelist") != "" {
		node.Whitelist, err = ParsePermissions(query.Get("whitelist"))

		if err != nil {
			glog.Fatal(err)
		}
	} else {
		// By default allow for everyting
		node.Whitelist, _ = ParsePermissions("*:*:*")
	}

	if query.Get("blacklist") != "" {
		node.Blacklist, err = ParsePermissions(query.Get("blacklist"))

		if err != nil {
			glog.Fatal(err)
		}
	} else {
		// By default block nothing
		node.Blacklist, _ = ParsePermissions("")
	}

	if u.User != nil {
		node.Users = append(node.Users, u.User)
	}

	users, er := parseUsers(node.Get("secrets"))
	if users != nil {
		node.Users = append(node.Users, users...)
	}
	if er != nil {
		glog.V(LWARNING).Infoln("secrets:", er)
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
	case "ws", "wss", "tls", "http2", "quic", "kcp", "redirect", "ssu", "pht", "ssh":
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
	case "http", "http2", "socks", "socks4", "socks4a", "socks5", "ss":
	default:
		node.Protocol = ""
	}

	return
}

func parseUsers(authFile string) (users []*url.Userinfo, err error) {
	if authFile == "" {
		return
	}

	file, err := os.Open(authFile)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		s := strings.SplitN(line, " ", 2)
		if len(s) == 1 {
			users = append(users, url.User(strings.TrimSpace(s[0])))
		} else if len(s) == 2 {
			users = append(users, url.UserPassword(strings.TrimSpace(s[0]), strings.TrimSpace(s[1])))
		}
	}

	err = scanner.Err()
	return
}

// Get get node parameter by key
func (node *ProxyNode) Get(key string) string {
	return node.values.Get(key)
}

func (node *ProxyNode) Can(action string, addr string) bool {
	if !strings.Contains(addr, ":") {
		addr = addr + ":80"
	}
	host, strport, err := net.SplitHostPort(addr)

	if err != nil {
		return false
	}

	port, err := strconv.Atoi(strport)

	if err != nil {
		return false
	}

	glog.V(LDEBUG).Infof("Can action: %s, host: %s, port %d", action, host, port)

	return node.Whitelist.Can(action, host, port) && !node.Blacklist.Can(action, host, port)
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

func (node *ProxyNode) caFile() string {
	return node.Get("ca")
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

func (node ProxyNode) String() string {
	return fmt.Sprintf("transport: %s, protocol: %s, addr: %s, whitelist: %v, blacklist: %v", node.Transport, node.Protocol, node.Addr, node.Whitelist, node.Blacklist)
}
