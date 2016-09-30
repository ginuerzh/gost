package gost

import (
	//"bufio"
	//"crypto/tls"
	//"encoding/base64"
	//"github.com/golang/glog"
	//"golang.org/x/net/http2"
	"io"
	"net"
	//"net/http"
	//"net/http/httputil"
	//"strings"
	"time"
)

// http2 client connection, wrapped up just like a net.Conn
type Http2ClientConn struct {
	r          io.Reader
	w          io.Writer
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (c *Http2ClientConn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *Http2ClientConn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *Http2ClientConn) Close() error {
	if rc, ok := c.r.(io.ReadCloser); ok {
		return rc.Close()
	}
	return nil
}

func (c *Http2ClientConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *Http2ClientConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Http2ClientConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *Http2ClientConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *Http2ClientConn) SetWriteDeadline(t time.Time) error {
	return nil
}
