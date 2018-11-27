package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"runtime"

	// _ "net/http/pprof"

	"github.com/ginuerzh/gost"
	"github.com/go-log/log"
)

var (
	configureFile string
	baseCfg       = &baseConfig{}
)

func init() {
	gost.SetLogger(&gost.LogLogger{})

	var (
		printVersion bool
	)

	flag.Var(&baseCfg.route.ChainNodes, "F", "forward address, can make a forward chain")
	flag.Var(&baseCfg.route.ServeNodes, "L", "listen address, can listen on multiple ports")
	flag.StringVar(&configureFile, "C", "", "configure file")
	flag.BoolVar(&baseCfg.Debug, "D", false, "enable debug log")
	flag.BoolVar(&printVersion, "V", false, "print version")
	flag.Parse()

	if printVersion {
		fmt.Fprintf(os.Stderr, "gost %s (%s %s/%s)\n",
			gost.Version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if configureFile != "" {
		_, err := parseBaseConfig(configureFile)
		if err != nil {
			log.Log(err)
			os.Exit(1)
		}
	}
	if flag.NFlag() == 0 || !baseCfg.IsValid() {
		flag.PrintDefaults()
		os.Exit(0)
	}
}

func main() {
	// go func() {
	// 	log.Log(http.ListenAndServe("localhost:6060", nil))
	// }()

	// NOTE: as of 2.6, you can use custom cert/key files to initialize the default certificate.
	tlsConfig, err := tlsConfig(defaultCertFile, defaultKeyFile)
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
	}
	gost.DefaultTLSConfig = tlsConfig

	start()

	select {}
}

func start() error {
	gost.Debug = baseCfg.Debug

	if err := baseCfg.route.serve(); err != nil {
		return err
	}
	for _, route := range baseCfg.Routes {
		if err := route.serve(); err != nil {
			return err
		}
	}

	go gost.PeriodReload(baseCfg, configureFile)

	return nil
}
