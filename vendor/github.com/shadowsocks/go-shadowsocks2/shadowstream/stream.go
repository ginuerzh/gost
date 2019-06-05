package shadowstream

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"net"
)

const bufSize = 32 * 1024

type writer struct {
	io.Writer
	cipher.Stream
	buf []byte
}

// NewWriter wraps an io.Writer with stream cipher encryption.
func NewWriter(w io.Writer, s cipher.Stream) io.Writer {
	return &writer{Writer: w, Stream: s, buf: make([]byte, bufSize)}
}

func (w *writer) ReadFrom(r io.Reader) (n int64, err error) {
	for {
		buf := w.buf
		nr, er := r.Read(buf)
		if nr > 0 {
			n += int64(nr)
			buf = buf[:nr]
			w.XORKeyStream(buf, buf)
			_, ew := w.Writer.Write(buf)
			if ew != nil {
				err = ew
				return
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.ReaderFrom contract
				err = er
			}
			return
		}
	}
}

func (w *writer) Write(b []byte) (int, error) {
	n, err := w.ReadFrom(bytes.NewBuffer(b))
	return int(n), err
}

type reader struct {
	io.Reader
	cipher.Stream
	buf []byte
}

// NewReader wraps an io.Reader with stream cipher decryption.
func NewReader(r io.Reader, s cipher.Stream) io.Reader {
	return &reader{Reader: r, Stream: s, buf: make([]byte, bufSize)}
}

func (r *reader) Read(b []byte) (int, error) {

	n, err := r.Reader.Read(b)
	if err != nil {
		return 0, err
	}
	b = b[:n]
	r.XORKeyStream(b, b)
	return n, nil
}

func (r *reader) WriteTo(w io.Writer) (n int64, err error) {
	for {
		buf := r.buf
		nr, er := r.Read(buf)
		if nr > 0 {
			nw, ew := w.Write(buf[:nr])
			n += int64(nw)

			if ew != nil {
				err = ew
				return
			}
		}

		if er != nil {
			if er != io.EOF { // ignore EOF as per io.Copy contract (using src.WriteTo shortcut)
				err = er
			}
			return
		}
	}
}

type conn struct {
	net.Conn
	Cipher
	r *reader
	w *writer
}

// NewConn wraps a stream-oriented net.Conn with stream cipher encryption/decryption.
func NewConn(c net.Conn, ciph Cipher) net.Conn {
	return &conn{Conn: c, Cipher: ciph}
}

func (c *conn) initReader() error {
	if c.r == nil {
		buf := make([]byte, bufSize)
		iv := buf[:c.IVSize()]
		if _, err := io.ReadFull(c.Conn, iv); err != nil {
			return err
		}
		c.r = &reader{Reader: c.Conn, Stream: c.Decrypter(iv), buf: buf}
	}
	return nil
}

func (c *conn) Read(b []byte) (int, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.Read(b)
}

func (c *conn) WriteTo(w io.Writer) (int64, error) {
	if c.r == nil {
		if err := c.initReader(); err != nil {
			return 0, err
		}
	}
	return c.r.WriteTo(w)
}

func (c *conn) initWriter() error {
	if c.w == nil {
		buf := make([]byte, bufSize)
		iv := buf[:c.IVSize()]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return err
		}
		if _, err := c.Conn.Write(iv); err != nil {
			return err
		}
		c.w = &writer{Writer: c.Conn, Stream: c.Encrypter(iv), buf: buf}
	}
	return nil
}

func (c *conn) Write(b []byte) (int, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.Write(b)
}

func (c *conn) ReadFrom(r io.Reader) (int64, error) {
	if c.w == nil {
		if err := c.initWriter(); err != nil {
			return 0, err
		}
	}
	return c.w.ReadFrom(r)
}
