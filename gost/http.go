package gost

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/go-log/log"
)

type httpConnector struct {
	User *url.Userinfo
}

func HTTPConnector(user *url.Userinfo) Connector {
	return &httpConnector{User: user}
}

func (c *httpConnector) Connect(ctx context.Context, conn net.Conn, addr string) (net.Conn, error) {
	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: addr},
		Host:       addr,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	req.Header.Set("Proxy-Connection", "keep-alive")

	if c.User != nil {
		s := c.User.String()
		if _, set := c.User.Password(); !set {
			s += ":"
		}
		req.Header.Set("Proxy-Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(s)))
	}

	if err := req.Write(conn); err != nil {
		return nil, err
	}

	if Debug {
		dump, _ := httputil.DumpRequest(req, false)
		log.Log(string(dump))
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}

	if Debug {
		dump, _ := httputil.DumpResponse(resp, false)
		log.Log(string(dump))
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", resp.Status)
	}

	return conn, nil
}
