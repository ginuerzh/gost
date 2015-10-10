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
	pv                              bool // print version

	listenArgs  []Args
	proxyArgs   []Args
	forwardArgs []Args
)

func init() {
	flag.StringVar(&listenUrl, "L", ":http", "local address")
	flag.StringVar(&forwardUrl, "S", "", "remote address")
	flag.StringVar(&proxyUrl, "P", "", "proxy address")
	flag.BoolVar(&pv, "V", false, "print version")

	flag.Parse()

	listenArgs = parseArgs(listenUrl)
	proxyArgs = parseArgs(proxyUrl)
	forwardArgs = parseArgs(forwardUrl)
}

func main() {
	defer glog.Flush()

	if pv {
		printVersion()
		return
	}

	if len(listenArgs) == 0 {
		glog.Fatalln("no listen addr")
	}

	var wg sync.WaitGroup
	for _, args := range listenArgs {
		wg.Add(1)
		go func(arg Args) {
			defer wg.Done()
			listenAndServe(arg)
		}(args)
	}
	wg.Wait()
}
