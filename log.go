package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

type BufferedLog struct {
	buffer *bytes.Buffer
	w      io.WriteCloser
}

func NewLog() *BufferedLog {
	return &BufferedLog{
		buffer: &bytes.Buffer{},
		w:      os.Stdout,
	}
}

func NewFileLog(file *os.File) *BufferedLog {
	return &BufferedLog{
		buffer: &bytes.Buffer{},
		w:      file,
	}
}

func (log *BufferedLog) Log(a ...interface{}) (int, error) {
	return fmt.Fprint(log.buffer, a...)
}

func (log *BufferedLog) Logln(a ...interface{}) (int, error) {
	return fmt.Fprintln(log.buffer, a...)
}

func (log *BufferedLog) Logf(format string, a ...interface{}) (int, error) {
	return fmt.Fprintf(log.buffer, format, a...)
}

func (log *BufferedLog) Flush() error {
	defer func() {
		if log.w != os.Stdout {
			log.w.Close()
		}
	}()

	_, err := log.buffer.WriteTo(log.w)
	return err
}
