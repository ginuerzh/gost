// +build windows

package gost

import (
	"errors"
)

type RedsocksTCPServer struct{}

func NewRedsocksTCPServer(base *ProxyServer) *RedsocksTCPServer {
	return &RedsocksTCPServer{}
}

func (s *RedsocksTCPServer) ListenAndServe() error {
	return errors.New("Not supported")
}
