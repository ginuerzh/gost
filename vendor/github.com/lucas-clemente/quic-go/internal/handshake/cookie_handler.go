package handshake

import (
	"net"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/utils"
)

type cookieHandler struct {
	callback func(net.Addr, *Cookie) bool

	cookieGenerator *CookieGenerator
}

var _ mint.CookieHandler = &cookieHandler{}

func newCookieHandler(callback func(net.Addr, *Cookie) bool) (*cookieHandler, error) {
	cookieGenerator, err := NewCookieGenerator()
	if err != nil {
		return nil, err
	}
	return &cookieHandler{
		callback:        callback,
		cookieGenerator: cookieGenerator,
	}, nil
}

func (h *cookieHandler) Generate(conn *mint.Conn) ([]byte, error) {
	if h.callback(conn.RemoteAddr(), nil) {
		return nil, nil
	}
	return h.cookieGenerator.NewToken(conn.RemoteAddr())
}

func (h *cookieHandler) Validate(conn *mint.Conn, token []byte) bool {
	data, err := h.cookieGenerator.DecodeToken(token)
	if err != nil {
		utils.Debugf("Couldn't decode cookie from %s: %s", conn.RemoteAddr(), err.Error())
		return false
	}
	return h.callback(conn.RemoteAddr(), data)
}
