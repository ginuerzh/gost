package gost

import (
	"crypto/rand"
	"crypto/tls"
	"net/http/httptest"
	"net/url"
	"testing"
)

func autoHTTPProxyRoundtrip(targetURL string, data []byte, clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   HTTPConnector(clientInfo),
		Transporter: TCPTransporter(),
	}
	server := &Server{
		Listener: ln,
		Handler: AutoHandler(
			UsersHandlerOption(serverInfo...),
		),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestAutoHTTPProxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range httpProxyTests {
		err := autoHTTPProxyRoundtrip(httpSrv.URL, sendData, tc.cliUser, tc.srvUsers)
		if err == nil {
			if tc.errStr != "" {
				t.Errorf("#%d should failed with error %s", i, tc.errStr)
			}
		} else {
			if tc.errStr == "" {
				t.Errorf("#%d got error %v", i, err)
			}
			if err.Error() != tc.errStr {
				t.Errorf("#%d got error %v, want %v", i, err, tc.errStr)
			}
		}
	}
}

func autoSocks5ProxyRoundtrip(targetURL string, data []byte, clientInfo *url.Userinfo, serverInfo []*url.Userinfo) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS5Connector(clientInfo),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  AutoHandler(UsersHandlerOption(serverInfo...)),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestAutoSOCKS5Proxy(t *testing.T) {
	cert, err := GenCertificate()
	if err != nil {
		panic(err)
	}
	DefaultTLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range socks5ProxyTests {
		err := autoSocks5ProxyRoundtrip(httpSrv.URL, sendData,
			tc.cliUser,
			tc.srvUsers,
		)
		if err == nil {
			if !tc.pass {
				t.Errorf("#%d should failed", i)
			}
		} else {
			// t.Logf("#%d %v", i, err)
			if tc.pass {
				t.Errorf("#%d got error: %v", i, err)
			}
		}
	}
}

func autoSOCKS4ProxyRoundtrip(targetURL string, data []byte, options ...HandlerOption) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4Connector(),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  AutoHandler(options...),
	}
	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestAutoSOCKS4Proxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	if err := autoSOCKS4ProxyRoundtrip(httpSrv.URL, sendData); err != nil {
		t.Errorf("got error: %v", err)
	}

	if err := autoSOCKS4ProxyRoundtrip(httpSrv.URL, sendData,
		UsersHandlerOption(url.UserPassword("admin", "123456"))); err == nil {
		t.Errorf("authentication required auto handler for SOCKS4 should failed")
	}
}

func autoSocks4aProxyRoundtrip(targetURL string, data []byte, options ...HandlerOption) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SOCKS4AConnector(),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  AutoHandler(options...),
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestAutoSOCKS4AProxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	if err := autoSocks4aProxyRoundtrip(httpSrv.URL, sendData); err != nil {
		t.Errorf("got error: %v", err)
	}

	if err := autoSocks4aProxyRoundtrip(httpSrv.URL, sendData,
		UsersHandlerOption(url.UserPassword("admin", "123456"))); err == nil {
		t.Errorf("authentication required auto handler for SOCKS4A should failed")
	}
}

func autoSSProxyRoundtrip(targetURL string, data []byte, clientInfo *url.Userinfo, serverInfo *url.Userinfo) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   ShadowConnector(clientInfo),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Handler:  AutoHandler(UsersHandlerOption(serverInfo)),
		Listener: ln,
	}

	go server.Run()
	defer server.Close()

	return proxyRoundtrip(client, server, targetURL, data)
}

func TestAutoSSProxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	for i, tc := range ssTests {
		err := autoSSProxyRoundtrip(httpSrv.URL, sendData,
			tc.clientCipher,
			tc.serverCipher,
		)
		if err == nil {
			t.Errorf("#%d should failed", i)
		}
	}
}
