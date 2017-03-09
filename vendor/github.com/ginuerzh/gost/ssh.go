// The ssh tunnel is inspired by easyssh(https://dev.justinjudd.org/justin/easyssh)

package gost

import (
	"encoding/binary"
	"fmt"
	"github.com/golang/glog"
	"golang.org/x/crypto/ssh"
	"net"
	"net/url"
	"strconv"
)

// Applicaple SSH Request types for Port Forwarding - RFC 4254 7.X
const (
	DirectForwardRequest       = "direct-tcpip"         // RFC 4254 7.2
	RemoteForwardRequest       = "tcpip-forward"        // RFC 4254 7.1
	ForwardedTCPReturnRequest  = "forwarded-tcpip"      // RFC 4254 7.2
	CancelRemoteForwardRequest = "cancel-tcpip-forward" // RFC 4254 7.1
)

type SSHServer struct {
	Addr    string
	Base    *ProxyServer
	Config  *ssh.ServerConfig
	Handler func(ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request)
}

func (s *SSHServer) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		glog.V(LWARNING).Infoln("[ssh] Listen:", err)
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			glog.V(LWARNING).Infoln("[ssh] Accept:", err)
			return err
		}

		go func(conn net.Conn) {
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.Config)
			if err != nil {
				glog.V(LWARNING).Infof("[ssh] %s -> %s : %s", conn.RemoteAddr(), s.Addr, err)
				return
			}
			defer sshConn.Close()

			if s.Handler == nil {
				s.Handler = s.handleSSHConn
			}

			glog.V(LINFO).Infof("[ssh] %s <-> %s", conn.RemoteAddr(), s.Addr)
			s.Handler(sshConn, chans, reqs)
			glog.V(LINFO).Infof("[ssh] %s >-< %s", conn.RemoteAddr(), s.Addr)
		}(conn)
	}
}

func (s *SSHServer) handleSSHConn(conn ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	quit := make(chan interface{})
	go func() {
		for req := range reqs {
			switch req.Type {
			case RemoteForwardRequest:
				go s.tcpipForwardRequest(conn, req, quit)
			default:
				// glog.V(LWARNING).Infoln("unknown channel type:", req.Type)
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	go func() {
		for newChannel := range chans {
			// Check the type of channel
			t := newChannel.ChannelType()
			switch t {
			case DirectForwardRequest:
				channel, requests, err := newChannel.Accept()
				if err != nil {
					glog.V(LINFO).Infoln("[ssh] Could not accept channel:", err)
					continue
				}
				p := directForward{}
				ssh.Unmarshal(newChannel.ExtraData(), &p)

				go ssh.DiscardRequests(requests)
				go s.directPortForwardChannel(channel, fmt.Sprintf("%s:%d", p.Host1, p.Port1))
			default:
				glog.V(LWARNING).Infoln("[ssh] Unknown channel type:", t)
				newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			}
		}
	}()

	conn.Wait()
	close(quit)
}

// directForward is structure for RFC 4254 7.2 - can be used for "forwarded-tcpip" and "direct-tcpip"
type directForward struct {
	Host1 string
	Port1 uint32
	Host2 string
	Port2 uint32
}

func (p directForward) String() string {
	return fmt.Sprintf("%s:%d -> %s:%d", p.Host2, p.Port2, p.Host1, p.Port1)
}

func (s *SSHServer) directPortForwardChannel(channel ssh.Channel, raddr string) {
	defer channel.Close()

	glog.V(LINFO).Infof("[ssh-tcp] %s - %s", s.Addr, raddr)

	conn, err := s.Base.Chain.Dial(raddr)
	if err != nil {
		glog.V(LINFO).Infof("[ssh-tcp] %s - %s : %s", s.Addr, raddr, err)
		return
	}
	defer conn.Close()

	glog.V(LINFO).Infof("[ssh-tcp] %s <-> %s", s.Addr, raddr)
	Transport(conn, channel)
	glog.V(LINFO).Infof("[ssh-tcp] %s >-< %s", s.Addr, raddr)
}

// tcpipForward is structure for RFC 4254 7.1 "tcpip-forward" request
type tcpipForward struct {
	Host string
	Port uint32
}

func (s *SSHServer) tcpipForwardRequest(sshConn ssh.Conn, req *ssh.Request, quit <-chan interface{}) {
	t := tcpipForward{}
	ssh.Unmarshal(req.Payload, &t)
	addr := fmt.Sprintf("%s:%d", t.Host, t.Port)
	glog.V(LINFO).Infoln("[ssh-rtcp] listening tcp", addr)
	ln, err := net.Listen("tcp", addr) //tie to the client connection
	if err != nil {
		glog.V(LWARNING).Infoln("[ssh-rtcp]", err)
		req.Reply(false, nil)
		return
	}
	defer ln.Close()

	replyFunc := func() error {
		if t.Port == 0 && req.WantReply { // Client sent port 0. let them know which port is actually being used
			_, port, err := getHostPortFromAddr(ln.Addr())
			if err != nil {
				return err
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(port))
			t.Port = uint32(port)
			return req.Reply(true, b[:])
		}
		return req.Reply(true, nil)
	}
	if err := replyFunc(); err != nil {
		glog.V(LWARNING).Infoln("[ssh-rtcp]", err)
		return
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil { // Unable to accept new connection - listener likely closed
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()

				p := directForward{}
				var err error

				var portnum int
				p.Host1 = t.Host
				p.Port1 = t.Port
				p.Host2, portnum, err = getHostPortFromAddr(conn.RemoteAddr())
				if err != nil {
					return
				}

				p.Port2 = uint32(portnum)
				ch, reqs, err := sshConn.OpenChannel(ForwardedTCPReturnRequest, ssh.Marshal(p))
				if err != nil {
					glog.V(1).Infoln("[ssh-rtcp] open forwarded channel:", err)
					return
				}
				defer ch.Close()
				go ssh.DiscardRequests(reqs)

				glog.V(LINFO).Infof("[ssh-rtcp] %s <-> %s", conn.RemoteAddr(), conn.LocalAddr())
				Transport(ch, conn)
				glog.V(LINFO).Infof("[ssh-rtcp] %s >-< %s", conn.RemoteAddr(), conn.LocalAddr())
			}(conn)
		}
	}()

	<-quit
}

func getHostPortFromAddr(addr net.Addr) (host string, port int, err error) {
	host, portString, err := net.SplitHostPort(addr.String())
	if err != nil {
		return
	}
	port, err = strconv.Atoi(portString)
	return
}

type PasswordCallbackFunc func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error)

func DefaultPasswordCallback(users []*url.Userinfo) PasswordCallbackFunc {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		for _, user := range users {
			u := user.Username()
			p, _ := user.Password()
			if u == conn.User() && p == string(password) {
				return nil, nil
			}
		}
		glog.V(LINFO).Infof("[ssh] %s -> %s : password rejected for %s", conn.RemoteAddr(), conn.LocalAddr(), conn.User())
		return nil, fmt.Errorf("password rejected for %s", conn.User())
	}
}
