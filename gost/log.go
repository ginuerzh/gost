package gost

import (
	"log"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

type LogLogger struct {
}

func (l *LogLogger) Log(v ...interface{}) {
	log.Println(v...)
}

func (l *LogLogger) Logf(format string, v ...interface{}) {
	log.Printf(format, v...)
}

type NopLogger struct {
}

func (l *NopLogger) Log(v ...interface{}) {
}

func (l *NopLogger) Logf(format string, v ...interface{}) {
}
