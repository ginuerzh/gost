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

// Log uses the standard log library log.Output
func (l *LogLogger) Log(v ...interface{}) {
	log.Output(3, fmt.Sprintln(v...))
}

// Logf uses the standard log library log.Output
func (l *LogLogger) Logf(format string, v ...interface{}) {
	log.Output(3, fmt.Sprintf(format, v...))
}

// NopLogger is a dummy logger that discards the log outputs
type NopLogger struct {
}

// Log does nothing
func (l *NopLogger) Log(v ...interface{}) {
}

// Logf does nothing
func (l *NopLogger) Logf(format string, v ...interface{}) {
}
