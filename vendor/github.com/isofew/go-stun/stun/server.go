package stun

import (
	"net"
	"sync"
)

func ListenAndServe(network, laddr string, config *Config) error {
	srv := NewServer(config)
	return srv.ListenAndServe(network, laddr)
}

type Server struct {
	agent *Agent

	mu    sync.RWMutex
	conns []net.PacketConn
}

func NewServer(config *Config) *Server {
	srv := &Server{agent: NewAgent(config)}
	srv.agent.Handler = srv
	return srv
}

func (srv *Server) ListenAndServe(network, laddr string) error {
	c, err := net.ListenPacket(network, laddr)
	if err != nil {
		return err
	}
	srv.addConn(c)
	defer srv.removeConn(c)
	// not using stop channel
	return srv.agent.ServePacket(c, make(chan struct{}))
}

func (srv *Server) ServeSTUN(msg *Message, from Transport) {
	if msg.Type == MethodBinding {
		to := from
		mapped := from.RemoteAddr()
		ip, port := SockAddr(from.LocalAddr())

		res := &Message{
			Type:        MethodBinding | KindResponse,
			Transaction: msg.Transaction,
			Attributes: []Attr{
				Addr(AttrXorMappedAddress, mapped),
				Addr(AttrMappedAddress, mapped),
			},
		}

		srv.mu.RLock()
		defer srv.mu.RUnlock()

		if ch, ok := msg.GetInt(AttrChangeRequest); ok && ch != 0 {
			for _, c := range srv.conns {
				chip, chport := SockAddr(c.LocalAddr())
				if chip.IsUnspecified() {
					continue
				}
				if ch&ChangeIP != 0 {
					if !ip.Equal(chip) {
						to = &packetConn{c, mapped}
						break
					}
				} else if ch&ChangePort != 0 {
					if ip.Equal(chip) && port != chport {
						to = &packetConn{c, mapped}
						break
					}
				}
			}
		}

		if len(srv.conns) < 2 {
			srv.agent.Send(res, to)
			return
		}

	other:
		for _, a := range srv.conns {
			aip, aport := SockAddr(a.LocalAddr())
			if aip.IsUnspecified() || !ip.Equal(aip) || port == aport {
				continue
			}
			for _, b := range srv.conns {
				bip, bport := SockAddr(b.LocalAddr())
				if bip.IsUnspecified() || bip.Equal(ip) || aport != bport {
					continue
				}
				res.Set(Addr(AttrOtherAddress, b.LocalAddr()))
				break other
			}
		}

		srv.agent.Send(res, to)
	}
}

func (srv *Server) addConn(c net.PacketConn) {
	srv.mu.Lock()
	srv.conns = append(srv.conns, c)
	srv.mu.Unlock()
}

func (srv *Server) removeConn(c net.PacketConn) {
	srv.mu.Lock()
	l := srv.conns
	for i, it := range l {
		if it == c {
			srv.conns = append(l[:i], l[i+1:]...)
			break
		}
	}
	srv.mu.Unlock()
}

func (srv *Server) Close() error {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	for _, it := range srv.conns {
		it.Close()
	}
	srv.conns = nil
	return nil
}
