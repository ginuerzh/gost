package gost

import (
	"crypto/tls"
	"errors"
	"github.com/go-log/log"
	"github.com/isofew/go-stun/stun"
	"github.com/lucas-clemente/quic-go"
	"gopkg.in/sorcix/irc.v2"
	"net"
	"sync"
	"time"
)

// This file exports three structs (initializers and methods):
// 1. P2PSocket, for signalling via IRC. it should be connected all the time
// 2. P2PTransporter uses P2PSocket to dial to the peer and start streaming via QUIC
//    connections could be interrupted, will recover by redialling on P2PSocket
// 3. P2PListener uses P2PSocket to accept incoming peers and their streams
//    connections could be interrupted, will drop any broken sessions with peers
// Proxy chain is not implemented. See comments below on p2pTransporter for more details.

// a helper wrapper for the Encode method
func ircSend(i *irc.Conn, command string, params ...string) error {
	return i.Encoder.Encode(&irc.Message{
		Command: command,
		Params:  params,
	})
}

// wait for the first msg satisfying condition, or timeout
func ircRecv(i *irc.Conn, condition func(*irc.Message) bool, timeout time.Duration) (
	msg *irc.Message, err error) {

	mChan := make(chan *irc.Message, 1)
	eChan := make(chan error, 1)

	go func() {
		for {
			msg, err := i.Decoder.Decode()
			if err != nil {
				eChan <- err
				break
			}
			if msg.Command[0] == '4' || msg.Command[0] == '5' {
				eChan <- errors.New("[p2p] ircRecv error code " + msg.Command)
				break
			}
			if condition(msg) {
				mChan <- msg
				break
			}
		}
	}()

	if timeout > 0 {
		select {
		case msg = <-mChan:
		case err = <-eChan:
		case <-time.After(timeout):
			err = errors.New("[p2p] ircRecv timed out")
		}
	} else {
		select {
		case msg = <-mChan:
		case err = <-eChan:
		}
	}

	return
}

// wait for a message from peer_ (leave blank for any)
func ircWaitForPeer(i *irc.Conn, peer_ string, timeout time.Duration) (
	peer string, peerAddr net.Addr, err error) {

	msg, err := ircRecv(i, func(msg *irc.Message) bool {
		return msg.Command == "PRIVMSG" &&
			(peer_ == msg.Name || peer_ == "")
	}, timeout)
	if err != nil {
		return
	}

	peer = msg.Name
	peerAddr, err = net.ResolveUDPAddr("udp", msg.Params[1])

	return
}

// all-in-one config covering socket, transporter and listener
// the option 'peer' shouldn't belong here, but I'm too lazy
// to create a seperate config type for transporter XD
type P2PConfig struct {
	// irc related
	Peer      string
	User      string
	Pass      string
	Addr      string
	PingIntvl time.Duration
	Timeout   time.Duration
	// others
	StunAddr string
	// quic will use default certs & timeouts and will always keepalive
	// since the authentication is done on irc server
	// and p2p connections need keepalive anyway
	// (probably should be configurable, leave for now)
}

// p2p socket for dialing and accepting udp connections
type p2pSocket struct {
	i *irc.Conn
	c *P2PConfig
}

// create a new p2p socket, all configs can be left empty except for user
// (and for peer if you are using the socket to dial)
func P2PSocket(c *P2PConfig) (p *p2pSocket, err error) {

	// default configs
	if c == nil || c.User == "" {
		err = errors.New("[p2p] must specify irc user")
		return
	}
	if c.Pass == "" {
		c.Pass = "*"
	}
	if c.Addr == "" {
		c.Addr = "chat.freenode.net:6666"
	}
	if c.PingIntvl == 0 {
		c.PingIntvl = 60 * time.Second
	}
	if c.Timeout == 0 {
		c.Timeout = 15 * time.Second
	}
	if c.StunAddr == "" {
		c.StunAddr = "stun2.l.google.com:19302"
	}

	// irc dial
	i, err := irc.Dial(c.Addr)
	if err != nil {
		return
	}
	p = &p2pSocket{
		i: i,
		c: c,
	}

	// irc login
	err = ircSend(p.i, "PASS", p.c.Pass)
	if err != nil {
		return
	}
	err = ircSend(p.i, "NICK", p.c.User)
	if err != nil {
		return
	}
	err = ircSend(p.i, "USER", p.c.User, "*", "*", "*")
	if err != nil {
		return
	}
	_, err = ircRecv(p.i, func(msg *irc.Message) bool {
		return msg.Command == "MODE"
	}, p.c.Timeout)
	if err != nil {
		return
	}

	// irc keepalive (ping)
	go func() {
		for {
			time.Sleep(p.c.PingIntvl)
			err := ircSend(p.i, "PING", p.c.Addr)
			if err != nil {
				break
			}
		}
	}()

	log.Log("[p2p] irc ready")

	return
}

// dial to peer
func (p *p2pSocket) Dial() (conn net.PacketConn, peerAddr net.Addr, err error) {

	if p.c.Peer == "" {
		err = errors.New("[p2p] must specify irc peer to dial")
		return
	}

	conn, addr, err := stun.Discover("stun:" + p.c.StunAddr)
	if err != nil {
		return
	}

	err = ircSend(p.i, "PRIVMSG", p.c.Peer, addr.String())
	if err != nil {
		return
	}

	_, peerAddr, err = ircWaitForPeer(p.i, p.c.Peer, p.c.Timeout)
	if err == nil {
		log.Log("[p2p] irc connected with", p.c.Peer, "at", peerAddr)
	}

	return
}

// accept from any peer
func (p *p2pSocket) Accept() (conn net.PacketConn, err error) {

	// wait indefintely for an unknown peer :)
	peer, peerAddr, err := ircWaitForPeer(p.i, "", 0)
	if err != nil {
		return
	}

	conn, addr, err := stun.Discover("stun:" + p.c.StunAddr)
	if err != nil {
		return
	}

	err = ircSend(p.i, "PRIVMSG", peer, addr.String())
	if err != nil {
		return
	}

	// since we are the receiving party in later's handshake process,
	// we need to send some dummy packets to open a hole on the firewall
	_, err = conn.WriteTo(make([]byte, 1), peerAddr)
	if err == nil {
		log.Log("[p2p] irc connected with", peer, "at", peerAddr)
	}

	return
}

// wrapper for quic.Stream to make it a net.Conn
type quicStream struct {
	s quic.Stream
}

// add three dummy methods
func (_ *quicStream) LocalAddr() net.Addr {
	return &net.UDPAddr{Port: 0}
}

func (_ *quicStream) RemoteAddr() net.Addr {
	return &net.UDPAddr{Port: 1}
}

func (_ *quicStream) SetWriteDeadline(t time.Time) error {
	return nil
}

// and inherits all other method
func (q *quicStream) Read(b []byte) (int, error) {
	return q.s.Read(b)
}

func (q *quicStream) Write(b []byte) (int, error) {
	return q.s.Write(b)
}

func (q *quicStream) Close() error {
	return q.s.Close()
}

func (q *quicStream) SetDeadline(t time.Time) error {
	return q.s.SetDeadline(t)
}

func (q *quicStream) SetReadDeadline(t time.Time) error {
	return q.s.SetReadDeadline(t)
}

// default quic config to use
var p2pQUICConfig = &quic.Config{
	MaxIncomingStreams:	65535,
	MaxIncomingUniStreams:	65535,
	KeepAlive:		true,
}

// (partially) implements gost's Transporter interface
// note that handshake, in particular, is not properly implemented
// so currently this node can only be used alone
// p.s.
// the difficulty is due to the heterogeneity of these 3 connections:
// 	one to the irc server for signalling, 			(1)
// 	one to the stun server for address discovery, 		(2)
//	and finally one quic session to our peer 		(3)
// we can't simply relay the message by an existing conn
// rather, we have to use one net.Conn interface for (1)
// and another net.PacketConn for (2) and (3)
// the latter is incompatible with the current interface in gost,
// so I decide to leave it unfinished for now.
type p2pTransporter struct {
	socket    *p2pSocket
	session   quic.Session
	dialMutex sync.Mutex
	dialling  bool
}

// creates a new p2pTransporter from config
// note that all dialing process is done here
// so it may takes a while to get ready
func P2PTransporter(config *P2PConfig) (p *p2pTransporter, err error) {

	socket, err := P2PSocket(config)
	if err != nil {
		return
	}
	p = &p2pTransporter{socket: socket}
	err = p.dial()
	return
}

// the actual dial that opens a session via irc signal
func (p *p2pTransporter) dial() (err error) {

	p.dialMutex.Lock()
	if p.dialling {
		return
	}
	p.dialling = true
	p.dialMutex.Unlock()

	pktConn, peerAddr, err := p.socket.Dial()
	if err != nil {
		return
	}
	p.session, err = quic.Dial(
		pktConn, peerAddr, peerAddr.String(),
		&tls.Config{InsecureSkipVerify: true},
		p2pQUICConfig)
	if err == nil {
		log.Log("[p2p] quic connected with", peerAddr)
	}

	p.dialling = false

	return
}

// open a stream to the already connected peer
// so not using addr or any dial options
func (p *p2pTransporter) Dial(_ string, _ ...DialOption) (
	conn net.Conn, err error) {

	stream, err := p.session.OpenStream()
	if err != nil {
		// try re-dialling
		p.dial()
		return
	}
	conn = &quicStream{
		s: stream,
	}

	return
}

// handshake func not implemented
func (p *p2pTransporter) Handshake(conn net.Conn, _ ...HandshakeOption) (
	net.Conn, error) {

	return conn, nil
}

// has multiplex support
func (p *p2pTransporter) Multiplex() bool {
	return true
}

// implements gost's Listener interface
type p2pListener struct {
	socket   *p2pSocket
	connChan chan net.Conn
	errChan  chan error
	stopChan chan struct{}
}

// creates a new p2pListener
func P2PListener(config *P2PConfig) (p *p2pListener, err error) {

	socket, err := P2PSocket(config)
	p = &p2pListener{
		socket:   socket,
		connChan: make(chan net.Conn),
		errChan:  make(chan error),
		stopChan: make(chan struct{}),
	}

	// outer loop: accept peers
	go func() {
		for {
			select {
			case <-p.stopChan:
				return
			default:
			}
			pktConn, err := p.socket.Accept()
			if err != nil {
				p.errChan <- err
				continue
			}
			// inner loop: accept streams for each peer
			go func() {
				ln, err := quic.Listen(
					pktConn,
					DefaultTLSConfig,
					p2pQUICConfig)
				if err != nil {
					p.errChan <- err
					return
				}
				session, err := ln.Accept()
				if err != nil {
					p.errChan <- err
					return
				}
				log.Log("[p2p] quic connected with", session.RemoteAddr())
				for {
					select {
					case <-p.stopChan:
						return
					default:
					}
					stream, err := session.AcceptStream()
					if err != nil {
						return
					}
					p.connChan <- &quicStream{
						s: stream,
					}
				}
			}()
		}
	}()

	return
}

// accept incoming connections from peers
func (p *p2pListener) Accept() (conn net.Conn, err error) {

	select {
	case conn = <-p.connChan:
	case err = <-p.errChan:
	}
	return
}

// close the underlying irc signal connection
// and stop all reading loops
func (p *p2pListener) Close() (err error) {

	err = p.socket.i.Close()
	close(p.stopChan)
	return
}

// a dummy addr method
func (p *p2pListener) Addr() net.Addr {
	return &net.UDPAddr{Port: 2}
}
