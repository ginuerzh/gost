package utils

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var out io.Writer = os.Stdout

// LogLevel of quic-go
type LogLevel uint8

const (
	// LogLevelDebug enables debug logs (e.g. packet contents)
	LogLevelDebug LogLevel = iota
	// LogLevelInfo enables info logs (e.g. packets)
	LogLevelInfo
	// LogLevelError enables err logs
	LogLevelError
	// LogLevelNothing disables
	LogLevelNothing
)

var logLevel = LogLevelNothing

var mutex sync.Mutex

// SetLogWriter sets the log writer.
func SetLogWriter(w io.Writer) {
	out = w
}

// SetLogLevel sets the log level
func SetLogLevel(level LogLevel) {
	logLevel = level
}

// Debugf logs something
func Debugf(format string, args ...interface{}) {
	if logLevel == LogLevelDebug {
		mutex.Lock()
		fmt.Fprintf(out, format+"\n", args...)
		mutex.Unlock()
	}
}

// Infof logs something
func Infof(format string, args ...interface{}) {
	if logLevel <= LogLevelInfo {
		mutex.Lock()
		fmt.Fprintf(out, format+"\n", args...)
		mutex.Unlock()
	}
}

// Errorf logs something
func Errorf(format string, args ...interface{}) {
	if logLevel <= LogLevelError {
		mutex.Lock()
		fmt.Fprintf(out, format+"\n", args...)
		mutex.Unlock()
	}
}

// Debug returns true if the log level is LogLevelDebug
func Debug() bool {
	return logLevel == LogLevelDebug
}
