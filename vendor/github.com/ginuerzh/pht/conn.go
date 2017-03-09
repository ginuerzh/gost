package pht

import (
	"errors"
	"io"
	"net"
	"time"
)

type conn struct {
	session        *session
	rb             []byte // read buffer
	remoteAddr     net.Addr
	localAddr      net.Addr
	rTimer, wTimer *time.Timer
	closed         chan interface{}
}

func newConn(session *session) *conn {
	conn := &conn{
		session: session,
		rTimer:  time.NewTimer(time.Hour * 65535),
		wTimer:  time.NewTimer(time.Hour * 65535),
		closed:  make(chan interface{}),
	}
	conn.rTimer.Stop()
	conn.wTimer.Stop()

	return conn
}

func (conn *conn) Read(b []byte) (n int, err error) {
	select {
	case <-conn.closed:
		err = errors.New("read: use of closed network connection")
		return
	default:
	}

	if len(conn.rb) > 0 {
		n = copy(b, conn.rb)
		conn.rb = conn.rb[n:]
		return
	}

	select {
	case data, ok := <-conn.session.rchan:
		if !ok {
			err = io.EOF
			return
		}
		n = copy(b, data)
		conn.rb = data[n:]
	case <-conn.rTimer.C:
		err = errors.New("read timeout")
	case <-conn.closed:
		err = io.EOF
	}

	return
}

func (conn *conn) Write(b []byte) (n int, err error) {
	select {
	case <-conn.closed:
		err = errors.New("write: use of closed network connection")
		return
	default:
	}

	if len(b) == 0 {
		return
	}

	data := make([]byte, len(b))
	copy(data, b)

	select {
	case conn.session.wchan <- data:
		n = len(b)
	case <-conn.wTimer.C:
		err = errors.New("write timeout")
	case <-conn.closed:
		err = errors.New("connection is closed")
	}

	return
}

func (conn *conn) Close() error {
	close(conn.closed)
	close(conn.session.closed)
	close(conn.session.wchan)
	return nil
}

func (conn *conn) LocalAddr() net.Addr {
	return conn.localAddr
}

func (conn *conn) RemoteAddr() net.Addr {
	return conn.remoteAddr
}

func (conn *conn) SetReadDeadline(t time.Time) error {
	if t.IsZero() {
		conn.rTimer.Stop()
		return nil
	}
	conn.rTimer.Reset(t.Sub(time.Now()))
	return nil
}

func (conn *conn) SetWriteDeadline(t time.Time) error {
	if t.IsZero() {
		conn.wTimer.Stop()
		return nil
	}
	conn.wTimer.Reset(t.Sub(time.Now()))
	return nil
}

func (conn *conn) SetDeadline(t time.Time) error {
	if t.IsZero() {
		conn.rTimer.Stop()
		conn.wTimer.Stop()
		return nil
	}
	d := t.Sub(time.Now())
	conn.rTimer.Reset(d)
	conn.wTimer.Reset(d)
	return nil
}
