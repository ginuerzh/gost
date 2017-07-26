package main

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/ginuerzh/gost/gost"
	"github.com/go-log/log"
)

type node struct {
	Addr       string
	Protocol   string          // protocol: http/socks5/ss
	Transport  string          // transport: ws/wss/tls/http2/tcp/udp/rtcp/rudp
	Remote     string          // remote address, used by tcp/udp port forwarding
	Users      []*url.Userinfo // authentication for proxy
	Whitelist  *gost.Permissions
	Blacklist  *gost.Permissions
	values     url.Values
	serverName string
}

func parseNode(s string) (n node, err error) {
	if !strings.Contains(s, "://") {
		s = "gost://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return
	}

	query := u.Query()

	n = node{
		Addr: u.Host,
	}

	if query.Get("whitelist") != "" {
		if n.Whitelist, err = gost.ParsePermissions(query.Get("whitelist")); err != nil {
			return
		}
	} else {
		// By default allow for everyting
		n.Whitelist, _ = gost.ParsePermissions("*:*:*")
	}

	if query.Get("blacklist") != "" {
		if n.Blacklist, err = gost.ParsePermissions(query.Get("blacklist")); err != nil {
			return
		}
	} else {
		// By default block nothing
		n.Blacklist, _ = gost.ParsePermissions("")
	}

	if u.User != nil {
		n.Users = append(n.Users, u.User)
	}

	users, er := parseUsers(n.values.Get("secrets"))
	if users != nil {
		n.Users = append(n.Users, users...)
	}
	if er != nil {
		log.Log("load secrets:", er)
	}

	if strings.Contains(u.Host, ":") {
		n.serverName, _, _ = net.SplitHostPort(u.Host)
		if n.serverName == "" {
			n.serverName = "localhost" // default server name
		}
	}

	schemes := strings.Split(u.Scheme, "+")
	if len(schemes) == 1 {
		n.Protocol = schemes[0]
		n.Transport = schemes[0]
	}
	if len(schemes) == 2 {
		n.Protocol = schemes[0]
		n.Transport = schemes[1]
	}

	switch n.Transport {
	case "ws", "wss", "tls", "h2", "h2c", "quic", "kcp", "redirect", "ssu", "ssh":
	case "https":
		n.Protocol = "http"
		n.Transport = "tls"
	case "http2": // http2 -> http2+tls, h2c mode is http2+tcp
		n.Protocol = "http2"
		n.Transport = "tls"
	case "tcp", "udp": // started from v2.1, tcp and udp are for local port forwarding
		n.Remote = strings.Trim(u.EscapedPath(), "/")
	case "rtcp", "rudp": // rtcp and rudp are for remote port forwarding
		n.Remote = strings.Trim(u.EscapedPath(), "/")
	default:
		n.Transport = ""
	}

	switch n.Protocol {
	case "http", "http2", "socks", "socks4", "socks4a", "socks5", "ss":
	default:
		n.Protocol = ""
	}

	return
}

func parseUsers(s string) (users []*url.Userinfo, err error) {
	if s == "" {
		return
	}

	f, err := os.Open(s)
	if err != nil {
		return
	}
	scanner := bufio.NewScanner(f)
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
