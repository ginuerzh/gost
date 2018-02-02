package quic

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/internal/protocol"
	"github.com/lucas-clemente/quic-go/internal/utils"
	"github.com/lucas-clemente/quic-go/internal/wire"
	"github.com/lucas-clemente/quic-go/qerr"
)

type client struct {
	mutex sync.Mutex

	conn     connection
	hostname string

	handshakeChan <-chan handshakeEvent

	versionNegotiationChan           chan struct{} // the versionNegotiationChan is closed as soon as the server accepted the suggested version
	versionNegotiated                bool          // has version negotiation completed yet
	receivedVersionNegotiationPacket bool

	tlsConf *tls.Config
	config  *Config

	connectionID protocol.ConnectionID
	version      protocol.VersionNumber

	session packetHandler
}

var (
	// make it possible to mock connection ID generation in the tests
	generateConnectionID         = utils.GenerateConnectionID
	errCloseSessionForNewVersion = errors.New("closing session in order to recreate it with a new version")
)

// DialAddr establishes a new QUIC connection to a server.
// The hostname for SNI is taken from the given address.
func DialAddr(addr string, tlsConf *tls.Config, config *Config) (Session, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return Dial(udpConn, udpAddr, addr, tlsConf, config)
}

// DialAddrNonFWSecure establishes a new QUIC connection to a server.
// The hostname for SNI is taken from the given address.
func DialAddrNonFWSecure(
	addr string,
	tlsConf *tls.Config,
	config *Config,
) (NonFWSession, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	return DialNonFWSecure(udpConn, udpAddr, addr, tlsConf, config)
}

// DialNonFWSecure establishes a new non-forward-secure QUIC connection to a server using a net.PacketConn.
// The host parameter is used for SNI.
func DialNonFWSecure(
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
) (NonFWSession, error) {
	connID, err := generateConnectionID()
	if err != nil {
		return nil, err
	}

	var hostname string
	if tlsConf != nil {
		hostname = tlsConf.ServerName
	}

	if hostname == "" {
		hostname, _, err = net.SplitHostPort(host)
		if err != nil {
			return nil, err
		}
	}

	clientConfig := populateClientConfig(config)
	c := &client{
		conn:                   &conn{pconn: pconn, currentAddr: remoteAddr},
		connectionID:           connID,
		hostname:               hostname,
		tlsConf:                tlsConf,
		config:                 clientConfig,
		version:                clientConfig.Versions[0],
		versionNegotiationChan: make(chan struct{}),
	}

	utils.Infof("Starting new connection to %s (%s -> %s), connectionID %x, version %s", hostname, c.conn.LocalAddr().String(), c.conn.RemoteAddr().String(), c.connectionID, c.version)

	if err := c.establishSecureConnection(); err != nil {
		return nil, err
	}
	return c.session.(NonFWSession), nil
}

// Dial establishes a new QUIC connection to a server using a net.PacketConn.
// The host parameter is used for SNI.
func Dial(
	pconn net.PacketConn,
	remoteAddr net.Addr,
	host string,
	tlsConf *tls.Config,
	config *Config,
) (Session, error) {
	sess, err := DialNonFWSecure(pconn, remoteAddr, host, tlsConf, config)
	if err != nil {
		return nil, err
	}
	if err := sess.WaitUntilHandshakeComplete(); err != nil {
		return nil, err
	}
	return sess, nil
}

// populateClientConfig populates fields in the quic.Config with their default values, if none are set
// it may be called with nil
func populateClientConfig(config *Config) *Config {
	if config == nil {
		config = &Config{}
	}
	versions := config.Versions
	if len(versions) == 0 {
		versions = protocol.SupportedVersions
	}

	handshakeTimeout := protocol.DefaultHandshakeTimeout
	if config.HandshakeTimeout != 0 {
		handshakeTimeout = config.HandshakeTimeout
	}
	idleTimeout := protocol.DefaultIdleTimeout
	if config.IdleTimeout != 0 {
		idleTimeout = config.IdleTimeout
	}

	maxReceiveStreamFlowControlWindow := config.MaxReceiveStreamFlowControlWindow
	if maxReceiveStreamFlowControlWindow == 0 {
		maxReceiveStreamFlowControlWindow = protocol.DefaultMaxReceiveStreamFlowControlWindowClient
	}
	maxReceiveConnectionFlowControlWindow := config.MaxReceiveConnectionFlowControlWindow
	if maxReceiveConnectionFlowControlWindow == 0 {
		maxReceiveConnectionFlowControlWindow = protocol.DefaultMaxReceiveConnectionFlowControlWindowClient
	}

	return &Config{
		Versions:                              versions,
		HandshakeTimeout:                      handshakeTimeout,
		IdleTimeout:                           idleTimeout,
		RequestConnectionIDOmission:           config.RequestConnectionIDOmission,
		MaxReceiveStreamFlowControlWindow:     maxReceiveStreamFlowControlWindow,
		MaxReceiveConnectionFlowControlWindow: maxReceiveConnectionFlowControlWindow,
		KeepAlive: config.KeepAlive,
	}
}

// establishSecureConnection returns as soon as the connection is secure (as opposed to forward-secure)
func (c *client) establishSecureConnection() error {
	if err := c.createNewSession(c.version, nil); err != nil {
		return err
	}
	go c.listen()

	var runErr error
	errorChan := make(chan struct{})
	go func() {
		// session.run() returns as soon as the session is closed
		runErr = c.session.run()
		if runErr == errCloseSessionForNewVersion {
			// run the new session
			runErr = c.session.run()
		}
		close(errorChan)
		utils.Infof("Connection %x closed.", c.connectionID)
		c.conn.Close()
	}()

	// wait until the server accepts the QUIC version (or an error occurs)
	select {
	case <-errorChan:
		return runErr
	case <-c.versionNegotiationChan:
	}

	select {
	case <-errorChan:
		return runErr
	case ev := <-c.handshakeChan:
		if ev.err != nil {
			return ev.err
		}
		if !c.version.UsesTLS() && ev.encLevel != protocol.EncryptionSecure {
			return fmt.Errorf("Client BUG: Expected encryption level to be secure, was %s", ev.encLevel)
		}
		return nil
	}
}

// Listen listens
func (c *client) listen() {
	var err error

	for {
		var n int
		var addr net.Addr
		data := getPacketBuffer()
		data = data[:protocol.MaxReceivePacketSize]
		// The packet size should not exceed protocol.MaxReceivePacketSize bytes
		// If it does, we only read a truncated packet, which will then end up undecryptable
		n, addr, err = c.conn.Read(data)
		if err != nil {
			if !strings.HasSuffix(err.Error(), "use of closed network connection") {
				c.session.Close(err)
			}
			break
		}
		data = data[:n]

		c.handlePacket(addr, data)
	}
}

func (c *client) handlePacket(remoteAddr net.Addr, packet []byte) {
	rcvTime := time.Now()

	r := bytes.NewReader(packet)
	hdr, err := wire.ParseHeaderSentByServer(r, c.version)
	if err != nil {
		utils.Errorf("error parsing packet from %s: %s", remoteAddr.String(), err.Error())
		// drop this packet if we can't parse the header
		return
	}
	// reject packets with truncated connection id if we didn't request truncation
	if hdr.OmitConnectionID && !c.config.RequestConnectionIDOmission {
		return
	}
	// reject packets with the wrong connection ID
	if !hdr.OmitConnectionID && hdr.ConnectionID != c.connectionID {
		return
	}
	hdr.Raw = packet[:len(packet)-r.Len()]

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if hdr.ResetFlag {
		cr := c.conn.RemoteAddr()
		// check if the remote address and the connection ID match
		// otherwise this might be an attacker trying to inject a PUBLIC_RESET to kill the connection
		if cr.Network() != remoteAddr.Network() || cr.String() != remoteAddr.String() || hdr.ConnectionID != c.connectionID {
			utils.Infof("Received a spoofed Public Reset. Ignoring.")
			return
		}
		pr, err := wire.ParsePublicReset(r)
		if err != nil {
			utils.Infof("Received a Public Reset. An error occurred parsing the packet: %s", err)
			return
		}
		utils.Infof("Received Public Reset, rejected packet number: %#x.", pr.RejectedPacketNumber)
		c.session.closeRemote(qerr.Error(qerr.PublicReset, fmt.Sprintf("Received a Public Reset for packet number %#x", pr.RejectedPacketNumber)))
		return
	}

	isVersionNegotiationPacket := hdr.VersionFlag /* gQUIC Version Negotiation Packet */ || hdr.Type == protocol.PacketTypeVersionNegotiation /* IETF draft style Version Negotiation Packet */

	// handle Version Negotiation Packets
	if isVersionNegotiationPacket {
		// ignore delayed / duplicated version negotiation packets
		if c.receivedVersionNegotiationPacket || c.versionNegotiated {
			return
		}

		// version negotiation packets have no payload
		if err := c.handleVersionNegotiationPacket(hdr); err != nil {
			c.session.Close(err)
		}
		return
	}

	// this is the first packet we are receiving
	// since it is not a Version Negotiation Packet, this means the server supports the suggested version
	if !c.versionNegotiated {
		c.versionNegotiated = true
		close(c.versionNegotiationChan)
	}

	c.session.handlePacket(&receivedPacket{
		remoteAddr: remoteAddr,
		header:     hdr,
		data:       packet[len(packet)-r.Len():],
		rcvTime:    rcvTime,
	})
}

func (c *client) handleVersionNegotiationPacket(hdr *wire.Header) error {
	for _, v := range hdr.SupportedVersions {
		if v == c.version {
			// the version negotiation packet contains the version that we offered
			// this might be a packet sent by an attacker (or by a terribly broken server implementation)
			// ignore it
			return nil
		}
	}

	c.receivedVersionNegotiationPacket = true

	newVersion, ok := protocol.ChooseSupportedVersion(c.config.Versions, hdr.SupportedVersions)
	if !ok {
		return qerr.InvalidVersion
	}

	// switch to negotiated version
	initialVersion := c.version
	c.version = newVersion
	var err error
	c.connectionID, err = utils.GenerateConnectionID()
	if err != nil {
		return err
	}
	utils.Infof("Switching to QUIC version %s. New connection ID: %x", newVersion, c.connectionID)

	// create a new session and close the old one
	// the new session must be created first to update client member variables
	oldSession := c.session
	defer oldSession.Close(errCloseSessionForNewVersion)
	return c.createNewSession(initialVersion, hdr.SupportedVersions)
}

func (c *client) createNewSession(initialVersion protocol.VersionNumber, negotiatedVersions []protocol.VersionNumber) error {
	var err error
	utils.Debugf("createNewSession with initial version %s", initialVersion)
	c.session, c.handshakeChan, err = newClientSession(
		c.conn,
		c.hostname,
		c.version,
		c.connectionID,
		c.tlsConf,
		c.config,
		initialVersion,
		negotiatedVersions,
	)
	return err
}
