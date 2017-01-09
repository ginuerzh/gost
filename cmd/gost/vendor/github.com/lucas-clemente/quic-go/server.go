package quic

import (
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/handshake"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

// packetHandler handles packets
type packetHandler interface {
	handlePacket(*receivedPacket)
	run()
	Close(error) error
}

// A Server of QUIC
type Server struct {
	addr *net.UDPAddr

	conn      *net.UDPConn
	connMutex sync.Mutex

	signer crypto.Signer
	scfg   *handshake.ServerConfig

	sessions      map[protocol.ConnectionID]packetHandler
	sessionsMutex sync.RWMutex

	streamCallback StreamCallback

	newSession func(conn connection, v protocol.VersionNumber, connectionID protocol.ConnectionID, sCfg *handshake.ServerConfig, streamCallback StreamCallback, closeCallback closeCallback) (packetHandler, error)
}

// NewServer makes a new server
func NewServer(addr string, tlsConfig *tls.Config, cb StreamCallback) (*Server, error) {
	signer, err := crypto.NewProofSource(tlsConfig)
	if err != nil {
		return nil, err
	}

	kex, err := crypto.NewCurve25519KEX()
	if err != nil {
		return nil, err
	}
	scfg, err := handshake.NewServerConfig(kex, signer)
	if err != nil {
		return nil, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}

	return &Server{
		addr:           udpAddr,
		signer:         signer,
		scfg:           scfg,
		streamCallback: cb,
		sessions:       map[protocol.ConnectionID]packetHandler{},
		newSession:     newSession,
	}, nil
}

// ListenAndServe listens and serves a connection
func (s *Server) ListenAndServe() error {
	conn, err := net.ListenUDP("udp", s.addr)
	if err != nil {
		return err
	}
	return s.Serve(conn)
}

// Serve on an existing UDP connection.
func (s *Server) Serve(conn *net.UDPConn) error {
	s.connMutex.Lock()
	s.conn = conn
	s.connMutex.Unlock()

	for {
		data := getPacketBuffer()
		data = data[:protocol.MaxPacketSize]
		n, remoteAddr, err := conn.ReadFromUDP(data)
		if err != nil {
			if strings.HasSuffix(err.Error(), "use of closed network connection") {
				return nil
			}
			return err
		}
		data = data[:n]
		if err := s.handlePacket(conn, remoteAddr, data); err != nil {
			utils.Errorf("error handling packet: %s", err.Error())
		}
	}
}

// Close the server
func (s *Server) Close() error {
	s.sessionsMutex.Lock()
	for _, session := range s.sessions {
		if session != nil {
			s.sessionsMutex.Unlock()
			_ = session.Close(nil)
			s.sessionsMutex.Lock()
		}
	}
	s.sessionsMutex.Unlock()

	s.connMutex.Lock()
	conn := s.conn
	s.conn = nil
	s.connMutex.Unlock()

	if conn == nil {
		return nil
	}
	return conn.Close()
}

func (s *Server) handlePacket(conn *net.UDPConn, remoteAddr *net.UDPAddr, packet []byte) error {
	if protocol.ByteCount(len(packet)) > protocol.MaxPacketSize {
		return qerr.PacketTooLarge
	}

	rcvTime := time.Now()

	r := bytes.NewReader(packet)

	hdr, err := ParsePublicHeader(r)
	if err != nil {
		return qerr.Error(qerr.InvalidPacketHeader, err.Error())
	}
	hdr.Raw = packet[:len(packet)-r.Len()]

	// Send Version Negotiation Packet if the client is speaking a different protocol version
	if hdr.VersionFlag && !protocol.IsSupportedVersion(hdr.VersionNumber) {
		utils.Infof("Client offered version %d, sending VersionNegotiationPacket", hdr.VersionNumber)
		_, err = conn.WriteToUDP(composeVersionNegotiation(hdr.ConnectionID), remoteAddr)
		return err
	}

	s.sessionsMutex.RLock()
	session, ok := s.sessions[hdr.ConnectionID]
	s.sessionsMutex.RUnlock()

	if !ok {
		utils.Infof("Serving new connection: %x, version %d from %v", hdr.ConnectionID, hdr.VersionNumber, remoteAddr)
		session, err = s.newSession(
			&udpConn{conn: conn, currentAddr: remoteAddr},
			hdr.VersionNumber,
			hdr.ConnectionID,
			s.scfg,
			s.streamCallback,
			s.closeCallback,
		)
		if err != nil {
			return err
		}
		go session.run()
		s.sessionsMutex.Lock()
		s.sessions[hdr.ConnectionID] = session
		s.sessionsMutex.Unlock()
	}
	if session == nil {
		// Late packet for closed session
		return nil
	}
	session.handlePacket(&receivedPacket{
		remoteAddr:   remoteAddr,
		publicHeader: hdr,
		data:         packet[len(packet)-r.Len():],
		rcvTime:      rcvTime,
	})
	return nil
}

func (s *Server) closeCallback(id protocol.ConnectionID) {
	s.sessionsMutex.Lock()
	s.sessions[id] = nil
	s.sessionsMutex.Unlock()
}

func composeVersionNegotiation(connectionID protocol.ConnectionID) []byte {
	fullReply := &bytes.Buffer{}
	responsePublicHeader := PublicHeader{
		ConnectionID: connectionID,
		PacketNumber: 1,
		VersionFlag:  true,
	}
	err := responsePublicHeader.WritePublicHeader(fullReply, protocol.Version35)
	if err != nil {
		utils.Errorf("error composing version negotiation packet: %s", err.Error())
	}
	fullReply.Write(protocol.SupportedVersionsAsTags)
	return fullReply.Bytes()
}
