package stun

import (
	"github.com/pkg/errors"
	"net"
)

type Conn struct {
	net.Conn
	agent *Agent
	sess  *Session
}

func NewConn(conn net.Conn, config *Config, stop chan struct{}) *Conn {
	a := NewAgent(config)
	go a.ServeConn(conn, stop)
	return &Conn{conn, a, nil}
}

func (c *Conn) Network() string {
	return c.LocalAddr().Network()
}

func (c *Conn) Discover() (net.Addr, error) {
	res, err := c.Request(&Message{Type: MethodBinding})
	if err != nil {
		return nil, err
	}
	mapped := res.GetAddr(c.Network(), AttrXorMappedAddress, AttrMappedAddress)
	if mapped != nil {
		return mapped, nil
	}
	return nil, errors.New("stun: bad response, no mapped address")
}

func (c *Conn) Request(req *Message) (res *Message, err error) {
	res, _, err = c.RequestTransport(req, c.Conn)
	return
}

func (c *Conn) RequestTransport(req *Message, to Transport) (res *Message, from Transport, err error) {
	sess := c.sess
	auth := c.agent.config.AuthMethod
	if to == nil {
		to = c.Conn
	}
	for {
		msg := &Message{
			req.Type,
			NewTransaction(),
			append(sess.attrs(), req.Attributes...),
		}
		res, from, err = c.agent.RoundTrip(msg, to)
		if err != nil {
			return
		}
		code := res.GetError()
		if code == nil {
			// FIXME: authorize response...
			if sess != nil {
				c.sess = sess
			}
			return
		}
		err = code
		switch code.Code {
		case CodeUnauthorized, CodeStaleNonce:
			if auth == nil {
				return
			}
			sess = &Session{
				Realm: res.GetString(AttrRealm),
				Nonce: res.GetString(AttrNonce),
			}
			if err = auth(sess); err != nil {
				return
			}
			auth = nil
		default:
			return
		}
	}
}

type Session struct {
	Realm    string
	Nonce    string
	Username string
	Key      []byte
}

func (s *Session) attrs() []Attr {
	if s == nil {
		return nil
	}
	var a []Attr
	if s.Realm != "" {
		a = append(a, String(AttrRealm, s.Realm))
	}
	if s.Nonce != "" {
		a = append(a, String(AttrNonce, s.Nonce))
	}
	if s.Username != "" {
		a = append(a, String(AttrUsername, s.Username))
	}
	if s.Key != nil {
		a = append(a, MessageIntegrity(s.Key))
	}
	return a
}
