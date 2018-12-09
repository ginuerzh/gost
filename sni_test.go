package gost

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"errors"
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
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(3 * time.Second))

	conn, err = client.Handshake(conn)
	if err != nil {
		return
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return
	}
	conn, err = client.Connect(conn, u.Host)
	if err != nil {
		return
	}

	if u.Scheme == "https" {
		conn = tls.Client(conn,
			&tls.Config{
				InsecureSkipVerify: false,
				ServerName:         u.Hostname(),
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

	return
}

func sniProxyRoundtrip(targetURL string, data []byte, host string) error {
	ln, err := TCPListener("")
	if err != nil {
		return err
	}

	client := &Client{
		Connector:   SNIConnector(host),
		Transporter: TCPTransporter(),
	}

	server := &Server{
		Listener: ln,
		Handler:  SNIHandler(),
	}

	go server.Run()
	defer server.Close()

	return sniRoundtrip(client, server, targetURL, data)
}

func TestSNIProxy(t *testing.T) {
	httpSrv := httptest.NewTLSServer(httpTestHandler)
	defer httpSrv.Close()

	sendData := make([]byte, 128)
	rand.Read(sendData)

	err := sniProxyRoundtrip("https://github.com", sendData, "")
	if err != nil {
		t.Errorf("got error: %v", err)
	}

	err = sniProxyRoundtrip("https://github.com", sendData, "google.com")
	if err != nil {
		t.Errorf("got error: %v", err)
	}
}
