package gost

import (
	"fmt"
	"log"
	"strings"
	"os"
)

//设置日志模式
func SetLogMode(LogMode string) {
	if LogMode != "" {
	var split []string = strings.Split(LogMode, ":")
	if split[0] == "file" {
    logFile, err := os.OpenFile(split[1], os.O_RDWR | os.O_CREATE | os.O_APPEND, 0770)
    if err != nil {
        panic(err.Error())
    } else {
        log.SetOutput(logFile)
    }
    //defer logFile.Close()
	}
	if split[0] == "shell" {
	if split[1] == "stdout" {
	log.SetOutput(os.Stdout)
	}
	}
	}
}

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
