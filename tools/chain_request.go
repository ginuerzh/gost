package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/ginuerzh/gost"
	"github.com/golang/glog"
	"golang.org/x/net/http2"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

var (
	proxyNodes stringlist
	urls       []string
)

func init() {
	flag.Var(&proxyNodes, "F", "forward address, can make a forward chain")
	flag.Parse()
	if flag.NArg() == 0 {
		log.Fatal("please specific at least one request URL")
	}
	urls = flag.Args()
	if glog.V(gost.LVDEBUG) {
		http2.VerboseLogs = true
	}
}

type stringlist []string

func (list *stringlist) String() string {
	return fmt.Sprintf("%s", *list)
}
func (list *stringlist) Set(value string) error {
	*list = append(*list, value)
	return nil
}

func main() {
	chain := gost.NewProxyChain()
	for _, s := range proxyNodes {
		node, err := gost.ParseProxyNode(s)
		if err != nil {
			log.Fatal(err)
		}
		chain.AddProxyNode(*node)
	}
	chain.Init()

	for _, u := range urls {
		url, err := url.Parse(u)
		if err != nil {
			log.Println("Invalid url:", u)
			continue
		}

		log.Println("GET", u)
		conn, err := chain.Dial(url.Host)
		if err != nil {
			log.Fatal(err)
		}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			log.Fatal(err)
		}

		if err := req.Write(conn); err != nil {
			log.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		if err != nil {
			log.Fatal(err)
		}
		defer resp.Body.Close()

		header, _ := httputil.DumpResponse(resp, false)
		log.Println(string(header))
	}

}
