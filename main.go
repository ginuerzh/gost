// main
package main

import (
	"flag"
	"github.com/golang/glog"
	"sync"
)

const (
	LFATAL = iota
	LERROR
	LWARNING
	LINFO
	LDEBUG
)

var (
	listenUrl, proxyUrl, forwardUrl string

	listenArgs  []Args
	proxyArgs   []Args
	forwardArgs []Args
)

func init() {
	flag.StringVar(&listenUrl, "L", ":http", "local address")
	flag.StringVar(&forwardUrl, "S", "", "remote address")
	flag.StringVar(&proxyUrl, "P", "", "proxy address")

	flag.Parse()

	listenArgs = parseArgs(listenUrl)
	proxyArgs = parseArgs(proxyUrl)
	forwardArgs = parseArgs(forwardUrl)
}

func main() {
	defer glog.Flush()

	if len(listenArgs) == 0 {
		glog.Fatalln("no listen addr")
	}

	var wg sync.WaitGroup

	for _, arg := range listenArgs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := listenAndServe(arg); err != nil {
				if glog.V(LFATAL) {
					glog.Errorln(err)
				}
			}
		}()
	}
	wg.Wait()
}
