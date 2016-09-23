// +build http2client

package main

import (
	"crypto/tls"
	"golang.org/x/net/http2"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	//"net/http/httputil"
	"os"
	"time"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	tr := http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
			return tls.DialWithDialer(&net.Dialer{Timeout: 30 * time.Second}, "tcp", "localhost:8080", cfg)
		},
	}
	client := http.Client{Transport: &tr}

	pr, pw := io.Pipe()

	req, err := http.NewRequest("CONNECT", "https://www.baidu.com", ioutil.NopCloser(pr))
	req.ContentLength = -1
	if err != nil {
		log.Fatal(err)
	}
	/*
		req := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Scheme: "https"},
			Host:   "www.baidu.com:443",
			Header: make(http.Header),
		}
	*/

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	r, err := http.NewRequest("GET", "https://www.baidu.com", nil)
	if err != nil {
		log.Fatal(err)
	}
	r.Write(pw)

	n, err := io.Copy(os.Stdout, resp.Body)
	log.Fatalf("copied %d, %v", n, err)
}
