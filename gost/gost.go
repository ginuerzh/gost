package gost

import (
	"github.com/go-log/log"
)

const Version = "2.4-dev20170722"

var Debug bool

var (
	SmallBufferSize  = 1 * 1024  // 1KB small buffer
	MediumBufferSize = 8 * 1024  // 8KB medium buffer
	LargeBufferSize  = 32 * 1024 // 32KB large buffer
)

func init() {
	log.DefaultLogger = &logger{}
}
