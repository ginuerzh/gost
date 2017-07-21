package gost

import "log"

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

type logger struct {
}

func (l *logger) Log(v ...interface{}) {
	log.Println(v...)
}

func (l *logger) Logf(format string, v ...interface{}) {
	log.Printf(format, v...)
}
