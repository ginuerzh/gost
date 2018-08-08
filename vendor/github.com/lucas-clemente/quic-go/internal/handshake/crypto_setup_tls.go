package handshake

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/bifurcation/mint"
	"github.com/lucas-clemente/quic-go/internal/crypto"
	"github.com/lucas-clemente/quic-go/internal/protocol"
)

// KeyDerivationFunction is used for key derivation
type KeyDerivationFunction func(crypto.TLSExporter, protocol.Perspective) (crypto.AEAD, error)

type cryptoSetupTLS struct {
	mutex sync.RWMutex

	perspective protocol.Perspective

	tls  mintTLS
	conn *fakeConn

	nextPacketType protocol.PacketType

	keyDerivation KeyDerivationFunction
	nullAEAD      crypto.AEAD
	aead          crypto.AEAD

	aeadChanged chan<- protocol.EncryptionLevel
}

// NewCryptoSetupTLSServer creates a new TLS CryptoSetup instance for a server
func NewCryptoSetupTLSServer(
	cryptoStream io.ReadWriter,
	connID protocol.ConnectionID,
	tlsConfig *tls.Config,
	remoteAddr net.Addr,
	params *TransportParameters,
	paramsChan chan<- TransportParameters,
	aeadChanged chan<- protocol.EncryptionLevel,
	checkCookie func(net.Addr, *Cookie) bool,
	supportedVersions []protocol.VersionNumber,
	version protocol.VersionNumber,
) (CryptoSetup, error) {
	mintConf, err := tlsToMintConfig(tlsConfig, protocol.PerspectiveServer)
	if err != nil {
		return nil, err
	}
	mintConf.RequireCookie = true
	mintConf.CookieHandler, err = newCookieHandler(checkCookie)
	if err != nil {
		return nil, err
	}
	conn := &fakeConn{
		stream:     cryptoStream,
		pers:       protocol.PerspectiveServer,
		remoteAddr: remoteAddr,
	}
	mintConn := mint.Server(conn, mintConf)
	eh := newExtensionHandlerServer(params, paramsChan, supportedVersions, version)
	if err := mintConn.SetExtensionHandler(eh); err != nil {
		return nil, err
	}

	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveServer, connID, version)
	if err != nil {
		return nil, err
	}

	return &cryptoSetupTLS{
		perspective:   protocol.PerspectiveServer,
		tls:           &mintController{mintConn},
		conn:          conn,
		nullAEAD:      nullAEAD,
		keyDerivation: crypto.DeriveAESKeys,
		aeadChanged:   aeadChanged,
	}, nil
}

// NewCryptoSetupTLSClient creates a new TLS CryptoSetup instance for a client
func NewCryptoSetupTLSClient(
	cryptoStream io.ReadWriter,
	connID protocol.ConnectionID,
	hostname string,
	tlsConfig *tls.Config,
	params *TransportParameters,
	paramsChan chan<- TransportParameters,
	aeadChanged chan<- protocol.EncryptionLevel,
	initialVersion protocol.VersionNumber,
	supportedVersions []protocol.VersionNumber,
	version protocol.VersionNumber,
) (CryptoSetup, error) {
	mintConf, err := tlsToMintConfig(tlsConfig, protocol.PerspectiveClient)
	if err != nil {
		return nil, err
	}
	mintConf.ServerName = hostname
	conn := &fakeConn{
		stream: cryptoStream,
		pers:   protocol.PerspectiveClient,
	}
	mintConn := mint.Client(conn, mintConf)
	eh := newExtensionHandlerClient(params, paramsChan, initialVersion, supportedVersions, version)
	if err := mintConn.SetExtensionHandler(eh); err != nil {
		return nil, err
	}

	nullAEAD, err := crypto.NewNullAEAD(protocol.PerspectiveClient, connID, version)
	if err != nil {
		return nil, err
	}

	return &cryptoSetupTLS{
		conn:           conn,
		perspective:    protocol.PerspectiveClient,
		tls:            &mintController{mintConn},
		nullAEAD:       nullAEAD,
		keyDerivation:  crypto.DeriveAESKeys,
		aeadChanged:    aeadChanged,
		nextPacketType: protocol.PacketTypeInitial,
	}, nil
}

func (h *cryptoSetupTLS) HandleCryptoStream() error {
handshakeLoop:
	for {
		switch alert := h.tls.Handshake(); alert {
		case mint.AlertNoAlert: // handshake complete
			break handshakeLoop
		case mint.AlertWouldBlock:
			h.determineNextPacketType()
			if err := h.conn.Continue(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("TLS handshake error: %s (Alert %d)", alert.String(), alert)
		}
	}

	aead, err := h.keyDerivation(h.tls, h.perspective)
	if err != nil {
		return err
	}
	h.mutex.Lock()
	h.aead = aead
	h.mutex.Unlock()

	// signal to the outside world that the handshake completed
	h.aeadChanged <- protocol.EncryptionForwardSecure
	close(h.aeadChanged)
	return nil
}

func (h *cryptoSetupTLS) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, protocol.EncryptionLevel, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.aead != nil {
		data, err := h.aead.Open(dst, src, packetNumber, associatedData)
		if err != nil {
			return nil, protocol.EncryptionUnspecified, err
		}
		return data, protocol.EncryptionForwardSecure, nil
	}
	data, err := h.nullAEAD.Open(dst, src, packetNumber, associatedData)
	if err != nil {
		return nil, protocol.EncryptionUnspecified, err
	}
	return data, protocol.EncryptionUnencrypted, nil
}

func (h *cryptoSetupTLS) GetSealer() (protocol.EncryptionLevel, Sealer) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.aead != nil {
		return protocol.EncryptionForwardSecure, h.aead
	}
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupTLS) GetSealerWithEncryptionLevel(encLevel protocol.EncryptionLevel) (Sealer, error) {
	errNoSealer := fmt.Errorf("CryptoSetup: no sealer with encryption level %s", encLevel.String())
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	switch encLevel {
	case protocol.EncryptionUnencrypted:
		return h.nullAEAD, nil
	case protocol.EncryptionForwardSecure:
		if h.aead == nil {
			return nil, errNoSealer
		}
		return h.aead, nil
	default:
		return nil, errNoSealer
	}
}

func (h *cryptoSetupTLS) GetSealerForCryptoStream() (protocol.EncryptionLevel, Sealer) {
	return protocol.EncryptionUnencrypted, h.nullAEAD
}

func (h *cryptoSetupTLS) determineNextPacketType() error {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	state := h.tls.State().HandshakeState
	if h.perspective == protocol.PerspectiveServer {
		switch state {
		case "ServerStateStart": // if we're still at ServerStateStart when writing the first packet, that means we've come back to that state by sending a HelloRetryRequest
			h.nextPacketType = protocol.PacketTypeRetry
		case "ServerStateWaitFinished":
			h.nextPacketType = protocol.PacketTypeHandshake
		default:
			// TODO: accept 0-RTT data
			return fmt.Errorf("Unexpected handshake state: %s", state)
		}
		return nil
	}
	// client
	if state != "ClientStateWaitSH" {
		h.nextPacketType = protocol.PacketTypeHandshake
	}
	return nil
}

func (h *cryptoSetupTLS) GetNextPacketType() protocol.PacketType {
	h.mutex.RLock()
	defer h.mutex.RUnlock()
	return h.nextPacketType
}

func (h *cryptoSetupTLS) DiversificationNonce() []byte {
	panic("diversification nonce not needed for TLS")
}

func (h *cryptoSetupTLS) SetDiversificationNonce([]byte) {
	panic("diversification nonce not needed for TLS")
}
