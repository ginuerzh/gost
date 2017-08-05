// obfs4 connection wrappers 

package gost

import (
	"fmt"
	"net"
	"net/url"
	"git.torproject.org/pluggable-transports/goptlib.git" // package pt
	"git.torproject.org/pluggable-transports/obfs4.git/transports/base"
    "git.torproject.org/pluggable-transports/obfs4.git/transports/obfs4"
)

// Factories are stored per node since some arguments reside in them.
// For simplicity, c & s variables are packed together.

type obfs4Context struct {
	cf      base.ClientFactory
	cargs   interface{} // type obfs4ClientArgs
	sf      base.ServerFactory
	sargs   *pt.Args
}
 
var obfs4Map = make(map[string]obfs4Context)

func (node *ProxyNode) obfs4GetContext() (obfs4Context, error) {
	if node.Transport != "obfs4" {
		return obfs4Context{}, fmt.Errorf("non-obfs4 node has no obfs4 context")
	}
	ctx, ok := obfs4Map[node.Addr]
	if !ok {
		return obfs4Context{}, fmt.Errorf("obfs4 context not inited")
	}
	return ctx, nil
}

func (node *ProxyNode) Obfs4Init(isServeNode bool) error {
	if _, ok := obfs4Map[node.Addr]; ok {
		return fmt.Errorf("obfs4 context already inited")
	}

	t := new(obfs4.Transport)

	stateDir := node.values.Get("state-dir")
	if stateDir == "" {
		stateDir = "."
	}

	ptArgs := pt.Args(node.values)

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

		fmt.Println("[obfs4 server inited]", node.Obfs4ServerURL())
	}

	return nil
}

func (node *ProxyNode) Obfs4ClientConn(conn net.Conn) (net.Conn, error) {
	ctx, err := node.obfs4GetContext()
	if err != nil {
		return nil, err
	}

	pseudoDial := func (a, b string) (net.Conn, error) {return conn, nil}
	return ctx.cf.Dial("tcp", "", pseudoDial, ctx.cargs)
}

func (node *ProxyNode) Obfs4ServerConn(conn net.Conn) (net.Conn, error) {
	ctx, err := node.obfs4GetContext()
	if err != nil {
		return nil, err
	}
	
	return ctx.sf.WrapConn(conn)
}

func (node *ProxyNode) Obfs4ServerURL() string {
	ctx, err := node.obfs4GetContext()
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
