package core

import "net"

type listener struct {
	net.Listener
	StreamConnCipher
}

func Listen(network, address string, ciph StreamConnCipher) (net.Listener, error) {
	l, err := net.Listen(network, address)
	return &listener{l, ciph}, err
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	return l.StreamConn(c), err
}

func Dial(network, address string, ciph StreamConnCipher) (net.Conn, error) {
	c, err := net.Dial(network, address)
	return ciph.StreamConn(c), err
}
