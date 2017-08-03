package gost

import (
	"fmt"
	"log"
)

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

// LogLogger uses the standard log package as the logger
type LogLogger struct {
}

func (l *LogLogger) Log(v ...interface{}) {
	log.Output(3, fmt.Sprintln(v...))
}

func (l *LogLogger) Logf(format string, v ...interface{}) {
	log.Output(3, fmt.Sprintf(format, v...))
}

// NopLogger is a null logger that discards the log outputs
type NopLogger struct {
}

func (l *NopLogger) Log(v ...interface{}) {
}

func (l *NopLogger) Logf(format string, v ...interface{}) {
}
