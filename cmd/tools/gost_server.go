package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/ginuerzh/gost"
	"log"
	"sync"
)

var (
	proxyNodes stringlist
)

func init() {
	flag.Var(&proxyNodes, "L", "proxy server node")
	flag.Parse()
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
	var wg sync.WaitGroup
	for _, ns := range proxyNodes {
		serverNode, err := gost.ParseProxyNode(ns)
		if err != nil {
			log.Println(err)
			continue
		}
		wg.Add(1)
		go func(node gost.ProxyNode) {
			defer wg.Done()
			cert, err := gost.LoadCertificate(node.Get("cert"), node.Get("key"))
			if err != nil {
				log.Println(err)
				return
			}
			server := gost.NewProxyServer(node, chain, &tls.Config{Certificates: []tls.Certificate{cert}})
			log.Fatal(server.Serve())
		}(serverNode)
	}
	wg.Wait()
}
