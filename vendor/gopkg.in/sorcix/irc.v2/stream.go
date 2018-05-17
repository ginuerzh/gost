// Copyright 2014 Vic Demuzere
//
// Use of this source code is governed by the MIT license.

package irc

import (
	"bufio"
	"io"
	"net"
	"crypto/tls"
	"sync"
)

// Messages are delimited with CR and LF line endings,
// we're using the last one to split the stream. Both are removed
// during message parsing.
const delim byte = '\n'

var endline = []byte("\r\n")

// A Conn represents an IRC network protocol connection.
// It consists of an Encoder and Decoder to manage I/O.
type Conn struct {
	Encoder
	Decoder

	conn io.ReadWriteCloser
}

// NewConn returns a new Conn using rwc for I/O.
func NewConn(rwc io.ReadWriteCloser) *Conn {
	return &Conn{
		Encoder: Encoder{
			writer: rwc,
		},
		Decoder: Decoder{
			reader: bufio.NewReader(rwc),
		},
		conn: rwc,
	}
}

// Dial connects to the given address using net.Dial and
// then returns a new Conn for the connection.
func Dial(addr string) (*Conn, error) {
	c, err := net.Dial("tcp", addr)

	if err != nil {
		return nil, err
	}

	return NewConn(c), nil
}

// DialTLS connects to the given address using tls.Dial and
// then returns a new Conn for the connection.
func DialTLS(addr string, config *tls.Config) (*Conn, error) {
	c, err := tls.Dial("tcp", addr, config)

	if err != nil {
		return nil, err
	}

	return NewConn(c), nil
}

// Close closes the underlying ReadWriteCloser.
func (c *Conn) Close() error {
	return c.conn.Close()
}

// A Decoder reads Message objects from an input stream.
type Decoder struct {
	reader *bufio.Reader
	line   string
	mu     sync.Mutex
}

// NewDecoder returns a new Decoder that reads from r.
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		reader: bufio.NewReader(r),
	}
}

// Decode attempts to read a single Message from the stream.
//
// Returns a non-nil error if the read failed.
func (dec *Decoder) Decode() (m *Message, err error) {

	dec.mu.Lock()
	dec.line, err = dec.reader.ReadString(delim)
	dec.mu.Unlock()

	if err != nil {
		return nil, err
	}

	return ParseMessage(dec.line), nil
}

// An Encoder writes Message objects to an output stream.
type Encoder struct {
	writer io.Writer
	mu     sync.Mutex
}

// NewEncoder returns a new Encoder that writes to w.
func NewEncoder(w io.Writer) *Encoder {
	return &Encoder{
		writer: w,
	}
}

// Encode writes the IRC encoding of m to the stream.
//
// This method may be used from multiple goroutines.
//
// Returns an non-nil error if the write to the underlying stream stopped early.
func (enc *Encoder) Encode(m *Message) (err error) {

	_, err = enc.Write(m.Bytes())

	return
}

// Write writes len(p) bytes from p followed by CR+LF.
//
// This method can be used simultaneously from multiple goroutines,
// it guarantees to serialize access. However, writing a single IRC message
// using multiple Write calls will cause corruption.
func (enc *Encoder) Write(p []byte) (n int, err error) {

	enc.mu.Lock()
	n, err = enc.writer.Write(p)

	if err != nil {
		enc.mu.Unlock()
		return
	}

	_, err = enc.writer.Write(endline)
	enc.mu.Unlock()

	return
}
