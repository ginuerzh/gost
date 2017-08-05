// obfs4 connection wrappers

package gost

import (
	"fmt"
	"net"
	"net/url"

	"github.com/go-log/log"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/base"
	"git.torproject.org/pluggable-transports/obfs4.git/transports/obfs4"
)

type obfs4Context struct {
	cf    base.ClientFactory
	cargs interface{} // type obfs4ClientArgs
	sf    base.ServerFactory
	sargs *pt.Args
}

var obfs4Map = make(map[string]obfs4Context)

func Obfs4Init(node Node, isServeNode bool) error {
	if _, ok := obfs4Map[node.Addr]; ok {
		return fmt.Errorf("obfs4 context already inited")
	}

	t := new(obfs4.Transport)

	stateDir := node.Values.Get("state-dir")
	if stateDir == "" {
		stateDir = "."
	}

	ptArgs := pt.Args(node.Values)

	if !isServeNode {
		cf, err := t.ClientFactory(stateDir)
		if err != nil {
			return err
		}

		cargs, err := cf.ParseArgs(&ptArgs)
		if err != nil {
			return err
		}

		obfs4Map[node.Addr] = obfs4Context{cf: cf, cargs: cargs}
	} else {
		sf, err := t.ServerFactory(stateDir, &ptArgs)
		if err != nil {
			return err
		}

		sargs := sf.Args()

		obfs4Map[node.Addr] = obfs4Context{sf: sf, sargs: sargs}

		log.Log("[obfs4] server inited:", obfs4ServerURL(node))
	}

	return nil
}

func obfs4GetContext(addr string) (obfs4Context, error) {
	ctx, ok := obfs4Map[addr]
	if !ok {
		return obfs4Context{}, fmt.Errorf("obfs4 context not inited")
	}
	return ctx, nil
}

func obfs4ServerURL(node Node) string {
	ctx, err := obfs4GetContext(node.Addr)
	if err != nil {
		return ""
	}

	values := (*url.Values)(ctx.sargs)
	query := values.Encode()
	return fmt.Sprintf(
		"%s+%s://%s/?%s", //obfs4-cert=%s&iat-mode=%s",
		node.Protocol,
		node.Transport,
		node.Addr,
		query,
	)
}

func obfs4ClientConn(addr string, conn net.Conn) (net.Conn, error) {
	ctx, err := obfs4GetContext(addr)
	if err != nil {
		return nil, err
	}

	pseudoDial := func(a, b string) (net.Conn, error) { return conn, nil }
	return ctx.cf.Dial("tcp", "", pseudoDial, ctx.cargs)
}

func obfs4ServerConn(addr string, conn net.Conn) (net.Conn, error) {
	ctx, err := obfs4GetContext(addr)
	if err != nil {
		return nil, err
	}

	return ctx.sf.WrapConn(conn)
}

type obfs4Transporter struct {
	tcpTransporter
}

// Obfs4Transporter creates a Transporter that is used by obfs4 client.
func Obfs4Transporter() Transporter {
	return &obfs4Transporter{}
}

func (tr *obfs4Transporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	opts := &HandshakeOptions{}
	for _, option := range options {
		option(opts)
	}
	return obfs4ClientConn(opts.Addr, conn)
}

type obfs4Listener struct {
	addr string
	net.Listener
}

// Obfs4Listener creates a Listener for obfs4 server.
func Obfs4Listener(addr string) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	l := &obfs4Listener{
		addr:     addr,
		Listener: ln,
	}
	return l, nil
}

func (l *obfs4Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cc, err := obfs4ServerConn(l.addr, conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return cc, nil
}
