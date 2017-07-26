package gost

import (
	"time"

	"github.com/go-log/log"
)

// Version is the gost version.
const Version = "2.4-dev20170722"

// Debug is a flag that enables the debug log.
var Debug bool

var (
	tinyBufferSize   = 128
	smallBufferSize  = 1 * 1024  // 1KB small buffer
	mediumBufferSize = 8 * 1024  // 8KB medium buffer
	largeBufferSize  = 32 * 1024 // 32KB large buffer
)

var (
	// KeepAliveTime is the keep alive time period for TCP connection.
	KeepAliveTime = 180 * time.Second
	// DialTimeout is the timeout of dial.
	DialTimeout = 30 * time.Second
	// ReadTimeout is the timeout for reading.
	ReadTimeout = 30 * time.Second
	// WriteTimeout is the timeout for writing.
	WriteTimeout = 60 * time.Second
	// PingTimeout is the timeout for pinging.
	PingTimeout = 30 * time.Second
	// PingRetries is the reties of ping.
	PingRetries = 3
	// default udp node TTL in second for udp port forwarding.
	defaultTTL = 60
)

func init() {
	log.DefaultLogger = &LogLogger{}
}

func SetLogger(logger log.Logger) {
	log.DefaultLogger = logger
}
