package gost

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func sniRoundtrip(client *Client, server *Server, targetURL string, data []byte) (err error) {
	conn, err := client.Dial(server.Addr().String())
	if err != nil {
		return
	}

	conn, err = client.Handshake(conn, AddrHandshakeOption(server.Addr().String()))
	if err != nil {
		return
	}
	defer conn.Close()

	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}

	conn.SetDeadline(time.Now().Add(3 * time.Second))
	defer conn.SetDeadline(time.Time{})

	conn, err = client.Connect(conn, u.Host)
	if err != nil {
		return
	}

	if u.Scheme == "https" {
		conn = tls.Client(conn,
			&tls.Config{
				InsecureSkipVerify: true,
				// ServerName:         u.Hostname(),
			})
		u.Scheme = "http"
	}
	req, err := http.NewRequest(
		http.MethodGet,
		u.String(),
		bytes.NewReader(data),
	)
	if err != nil {
		return
	}
	if err = req.Write(conn); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	recv, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if !bytes.Equal(data, recv) {
		return fmt.Errorf("data not equal")
	}

	return
}

func sniProxyRoundtrip(targetURL string, data []byte, host string) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SNIConnector(host),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SNIHandler(HostHandlerOption(u.Host)),
	}

	go server.Run()
	defer server.Close()

	return sniRoundtrip(client, server, targetURL, data)
}

func TestSNIProxy(t *testing.T) {
	httpSrv := httptest.NewServer(httpTestHandler)
	defer httpSrv.Close()

	httpsSrv := httptest.NewTLSServer(httpTestHandler)
	defer httpsSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	var sniProxyTests = []struct {
		targetURL string
		host      string
		pass      bool
	}{
		{httpSrv.URL, "", true},
		{httpSrv.URL, "example.com", true},
		{httpsSrv.URL, "", true},
		{httpsSrv.URL, "example.com", true},
	}

	for i, tc := range sniProxyTests {
		tc := tc
		t.Run(fmt.Sprintf("#%d", i), func(t *testing.T) {
			err := sniProxyRoundtrip(tc.targetURL, sendData, tc.host)
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
		})
	}
}
