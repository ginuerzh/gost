package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

var (
	Debug bool
)

type BufferedLog struct {
	buffer *bytes.Buffer
	w      io.WriteCloser
}

func NewLog(buffered bool) *BufferedLog {
	log := &BufferedLog{
		w: os.Stdout,
	}
	if buffered {
		log.buffer = &bytes.Buffer{}
	}

	return log
}

func NewFileLog(file *os.File) *BufferedLog {
	return &BufferedLog{
		buffer: &bytes.Buffer{},
		w:      file,
	}
}

func (log *BufferedLog) Log(a ...interface{}) (int, error) {
	if !Debug {
		return 0, nil
	}
	if log.buffer != nil {
		return fmt.Fprint(log.buffer, a...)
	}
	return fmt.Fprint(log.w, a...)
}

func (log *BufferedLog) Logln(a ...interface{}) (int, error) {
	if !Debug {
		return 0, nil
	}
	if log.buffer != nil {
		return fmt.Fprintln(log.buffer, a...)
	}
	return fmt.Fprintln(log.w, a...)
}

func (log *BufferedLog) Logf(format string, a ...interface{}) (int, error) {
	if !Debug {
		return 0, nil
	}
	if log.buffer != nil {
		return fmt.Fprintf(log.buffer, format, a...)
	}
	return fmt.Fprintf(log.w, format, a...)
}

func (log *BufferedLog) Flush() error {
	defer func() {
		if log.w != os.Stdout {
			log.w.Close()
		}
	}()

	if !Debug || log.buffer == nil {
		return nil
	}

	_, err := log.buffer.WriteTo(log.w)
	return err
}
