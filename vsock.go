package gost

import (
	"net"
	"strconv"

	"github.com/mdlayher/vsock"
)

// vsockTransporter is a raw VSOCK transporter.
type vsockTransporter struct{}

// VSOCKTransporter creates a raw VSOCK client.
func VSOCKTransporter() Transporter {
	return &vsockTransporter{}
}

func (tr *vsockTransporter) Dial(addr string, options ...DialOption) (net.Conn, error) {
	opts := &DialOptions{}
	for _, option := range options {
		option(opts)
	}
	if opts.Chain == nil {
		vAddr, err := parseAddr(addr)
		if err != nil {
			return nil, err
		}
		return vsock.Dial(vAddr.ContextID, vAddr.Port, nil)
	}
	return opts.Chain.Dial(addr)
}

func parseUint32(s string) (uint32, error ) {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(n), nil
}

func parseAddr(addr string) (*vsock.Addr, error) {
	hostStr, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	host := uint32(0)
	if hostStr != "" {
		host, err = parseUint32(hostStr)
		if err != nil {
			return nil, err
		}
	}

	port, err := parseUint32(portStr)
	if err != nil {
		return nil, err
	}
	return &vsock.Addr{ContextID: host, Port: port}, nil
}

func (tr *vsockTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *vsockTransporter) Multiplex() bool {
	return false
}

// VSOCKListener creates a Listener for VSOCK proxy server.
func VSOCKListener(addr string) (Listener, error) {
	vAddr, err := parseAddr(addr)
	if err != nil {
		return nil, err
	}
	return vsock.Listen(vAddr.Port, nil)
}
