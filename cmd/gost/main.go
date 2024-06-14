package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sync"
	"strings"
	"runtime"

	_ "net/http/pprof"

	"github.com/ginuerzh/gost"
	"github.com/go-log/log"
)

var (
	pprofEnabled  = os.Getenv("PROFILING") != ""
)

func init() {
	gost.SetLogger(&gost.LogLogger{})

	// TODO - Generate different certificates for each worker
	generateTLSCertificate()
}

func main() {
	var wg sync.WaitGroup
	wg.Add(1)  // Gost must exit if any of the workers exit

	// Split os.Args using -- and create a worker with each slice
	args := strings.Split(" " + strings.Join(os.Args[1:], "  ") + " ", " -- ")
	if strings.Join(args, "") == "" {
		// Fix to show gost help if the resulting array is empty
		args[0] = " "
	}
	for wid, wargs := range args {
		if wargs != "" {
			go worker(wid, wargs, &wg)
		}
	}
	wg.Wait()
}

func worker(id int, args string, wg *sync.WaitGroup) {
	defer wg.Done()

	var (
		configureFile string
		baseCfg       = &baseConfig{}
		pprofAddr     string
	)

	init := func () error {
		var printVersion bool

		wf := flag.NewFlagSet(os.Args[0], flag.ExitOnError)

		wf.Var(&baseCfg.route.ChainNodes, "F", "forward address, can make a forward chain")
		wf.Var(&baseCfg.route.ServeNodes, "L", "listen address, can listen on multiple ports (required)")
		wf.StringVar(&configureFile, "C", "", "configure file")
		wf.BoolVar(&baseCfg.Debug, "D", false, "enable debug log")
		wf.BoolVar(&printVersion, "V", false, "print version")

		if pprofEnabled {
			// Every worker uses a different profiling server by default
			wf.StringVar(&pprofAddr, "P", fmt.Sprintf(":606%d", id), "profiling HTTP server address")
		}

		wf.Parse(strings.Fields(args))

		if printVersion {
			fmt.Fprintf(os.Stdout, "gost %s (%s %s/%s)\n", gost.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			os.Exit(0)
		} else if wf.NFlag() == 0 {
			wf.Usage()
			os.Exit(0)
		} else if configureFile != "" {
			err := parseBaseConfig(configureFile, baseCfg)
			if err != nil {
				return err
			}
		}

		if baseCfg.route.ServeNodes.String() == "[]" {
			configErrMsg := ""
			if configureFile != "" {
				configErrMsg = " or ServeNodes inside config file (-C)"
			}
			fmt.Fprintf(os.Stderr, "\n[!] Error: Missing -L flag%s\n\n", configErrMsg)
			wf.Usage()
			os.Exit(1)
		}

		return nil
	}

	start := func () error {
		// TODO - Make debug worker independent
		if ! gost.Debug {
			gost.Debug = baseCfg.Debug
		}

		var routers []router
		rts, err := baseCfg.route.GenRouters()
		if err != nil {
			return err
		}
		routers = append(routers, rts...)

		for _, route := range baseCfg.Routes {
			rts, err := route.GenRouters()
			if err != nil {
				return err
			}
			routers = append(routers, rts...)
		}

		if len(routers) == 0 {
			return errors.New("invalid config")
		}
		for i := range routers {
			go routers[i].Serve()
		}

		return nil
	}

	main := func () error {
		if pprofEnabled {
			go func() {
				log.Log("profiling server on", pprofAddr)
				log.Log(http.ListenAndServe(pprofAddr, nil))
			}()
		}

		err := start()
		return err
	}

	if err := init(); err != nil {
		log.Log(err)
		return
	}
	if err := main(); err != nil {
		log.Log(err)
		return
	}

	// Allow local functions to be garbage-collected
	init = nil
	main = nil
	start = nil

	select {}
}

func generateTLSCertificate() {
	// NOTE: as of 2.6, you can use custom cert/key files to initialize the default certificate.
	tlsConfig, err := tlsConfig(defaultCertFile, defaultKeyFile, "")
	if err != nil {
		// generate random self-signed certificate.
		cert, err := gost.GenCertificate()
		if err != nil {
			log.Log(err)
			os.Exit(1)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	} else {
		log.Log("load TLS certificate files OK")
	}
	gost.DefaultTLSConfig = tlsConfig
}
