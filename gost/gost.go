package gost

import (
	"time"

	"github.com/go-log/log"
)

const Version = "2.4-dev20170722"

var Debug bool

var (
	TinyBufferSize   = 128
	SmallBufferSize  = 1 * 1024  // 1KB small buffer
	MediumBufferSize = 8 * 1024  // 8KB medium buffer
	LargeBufferSize  = 32 * 1024 // 32KB large buffer
)

var (
	KeepAliveTime = 180 * time.Second
	DialTimeout   = 30 * time.Second
	ReadTimeout   = 90 * time.Second
	WriteTimeout  = 90 * time.Second

	DefaultTTL = 60 // default udp node TTL in second for udp port forwarding
)

func init() {
	log.DefaultLogger = &logger{}
}
