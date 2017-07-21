package gost

import (
	"github.com/go-log/log"
)

var Debug bool

func init() {
	log.DefaultLogger = &logger{}
}
