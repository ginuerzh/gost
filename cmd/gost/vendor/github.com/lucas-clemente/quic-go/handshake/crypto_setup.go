package handshake

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

// KeyDerivationFunction is used for key derivation
type KeyDerivationFunction func(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte) (crypto.AEAD, error)

// KeyExchangeFunction is used to make a new KEX
type KeyExchangeFunction func() crypto.KeyExchange

// The CryptoSetup handles all things crypto for the Session
type CryptoSetup struct {
	connID               protocol.ConnectionID
	ip                   net.IP
	version              protocol.VersionNumber
	scfg                 *ServerConfig
	diversificationNonce []byte

	secureAEAD                  crypto.AEAD
	forwardSecureAEAD           crypto.AEAD
	receivedForwardSecurePacket bool
	receivedSecurePacket        bool
	aeadChanged                 chan struct{}

	keyDerivation KeyDerivationFunction
	keyExchange   KeyExchangeFunction

	cryptoStream utils.Stream

	connectionParametersManager *ConnectionParametersManager

	mutex sync.RWMutex
}

var _ crypto.AEAD = &CryptoSetup{}

// NewCryptoSetup creates a new CryptoSetup instance
func NewCryptoSetup(
	connID protocol.ConnectionID,
	ip net.IP,
	version protocol.VersionNumber,
	scfg *ServerConfig,
	cryptoStream utils.Stream,
	connectionParametersManager *ConnectionParametersManager,
	aeadChanged chan struct{},
) (*CryptoSetup, error) {
	return &CryptoSetup{
		connID:                      connID,
		ip:                          ip,
		version:                     version,
		scfg:                        scfg,
		keyDerivation:               crypto.DeriveKeysAESGCM,
		keyExchange:                 getEphermalKEX,
		cryptoStream:                cryptoStream,
		connectionParametersManager: connectionParametersManager,
		aeadChanged:                 aeadChanged,
	}, nil
}

// HandleCryptoStream reads and writes messages on the crypto stream
func (h *CryptoSetup) HandleCryptoStream() error {
	for {
		var chloData bytes.Buffer
		messageTag, cryptoData, err := ParseHandshakeMessage(io.TeeReader(h.cryptoStream, &chloData))
		if err != nil {
			return qerr.HandshakeFailed
		}
		if messageTag != TagCHLO {
			return qerr.InvalidCryptoMessageType
		}

		utils.Debugf("Got CHLO:\n%s", printHandshakeMessage(cryptoData))

		done, err := h.handleMessage(chloData.Bytes(), cryptoData)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

func (h *CryptoSetup) handleMessage(chloData []byte, cryptoData map[Tag][]byte) (bool, error) {
	sniSlice, ok := cryptoData[TagSNI]
	if !ok {
		return false, qerr.Error(qerr.CryptoMessageParameterNotFound, "SNI required")
	}
	sni := string(sniSlice)
	if sni == "" {
		return false, qerr.Error(qerr.CryptoMessageParameterNotFound, "SNI required")
	}

	var reply []byte
	var err error
	if !h.isInchoateCHLO(cryptoData) {
		// We have a CHLO with a proper server config ID, do a 0-RTT handshake
		reply, err = h.handleCHLO(sni, chloData, cryptoData)
		if err != nil {
			return false, err
		}
		_, err = h.cryptoStream.Write(reply)
		if err != nil {
			return false, err
		}
		return true, nil
	}

	// We have an inchoate or non-matching CHLO, we now send a rejection
	reply, err = h.handleInchoateCHLO(sni, chloData, cryptoData)
	if err != nil {
		return false, err
	}
	_, err = h.cryptoStream.Write(reply)
	if err != nil {
		return false, err
	}
	return false, nil
}

// Open a message
func (h *CryptoSetup) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	if h.forwardSecureAEAD != nil {
		res, err := h.forwardSecureAEAD.Open(dst, src, packetNumber, associatedData)
		if err == nil {
			h.receivedForwardSecurePacket = true
			return res, nil
		}
		if h.receivedForwardSecurePacket {
			return nil, err
		}
	}
	if h.secureAEAD != nil {
		res, err := h.secureAEAD.Open(dst, src, packetNumber, associatedData)
		if err == nil {
			h.receivedSecurePacket = true
			return res, nil
		}
		if h.receivedSecurePacket {
			return nil, err
		}
	}
	return (&crypto.NullAEAD{}).Open(dst, src, packetNumber, associatedData)
}

// Seal a message, call LockForSealing() before!
func (h *CryptoSetup) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	if h.receivedForwardSecurePacket {
		return h.forwardSecureAEAD.Seal(dst, src, packetNumber, associatedData)
	} else if h.secureAEAD != nil {
		return h.secureAEAD.Seal(dst, src, packetNumber, associatedData)
	} else {
		return (&crypto.NullAEAD{}).Seal(dst, src, packetNumber, associatedData)
	}
}

func (h *CryptoSetup) isInchoateCHLO(cryptoData map[Tag][]byte) bool {
	scid, ok := cryptoData[TagSCID]
	if !ok || !bytes.Equal(h.scfg.ID, scid) {
		return true
	}
	if _, ok := cryptoData[TagPUBS]; !ok {
		return true
	}
	if err := h.scfg.stkSource.VerifyToken(h.ip, cryptoData[TagSTK]); err != nil {
		utils.Infof("STK invalid: %s", err.Error())
		return true
	}
	return false
}

func (h *CryptoSetup) handleInchoateCHLO(sni string, chlo []byte, cryptoData map[Tag][]byte) ([]byte, error) {
	if len(chlo) < protocol.ClientHelloMinimumSize {
		return nil, qerr.Error(qerr.CryptoInvalidValueLength, "CHLO too small")
	}

	token, err := h.scfg.stkSource.NewToken(h.ip)
	if err != nil {
		return nil, err
	}

	replyMap := map[Tag][]byte{
		TagSCFG: h.scfg.Get(),
		TagSTK:  token,
		TagSVID: []byte("quic-go"),
	}

	if h.scfg.stkSource.VerifyToken(h.ip, cryptoData[TagSTK]) == nil {
		proof, err := h.scfg.Sign(sni, chlo)
		if err != nil {
			return nil, err
		}

		commonSetHashes := cryptoData[TagCCS]
		cachedCertsHashes := cryptoData[TagCCRT]

		certCompressed, err := h.scfg.GetCertsCompressed(sni, commonSetHashes, cachedCertsHashes)
		if err != nil {
			return nil, err
		}
		// Token was valid, send more details
		replyMap[TagPROF] = proof
		replyMap[TagCERT] = certCompressed
	}

	var serverReply bytes.Buffer
	WriteHandshakeMessage(&serverReply, TagREJ, replyMap)
	return serverReply.Bytes(), nil
}

func (h *CryptoSetup) handleCHLO(sni string, data []byte, cryptoData map[Tag][]byte) ([]byte, error) {
	// We have a CHLO matching our server config, we can continue with the 0-RTT handshake
	sharedSecret, err := h.scfg.kex.CalculateSharedKey(cryptoData[TagPUBS])
	if err != nil {
		return nil, err
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	certUncompressed, err := h.scfg.signer.GetLeafCert(sni)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 32)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}

	h.diversificationNonce = make([]byte, 32)
	if _, err = rand.Read(h.diversificationNonce); err != nil {
		return nil, err
	}

	h.secureAEAD, err = h.keyDerivation(
		false,
		sharedSecret,
		cryptoData[TagNONC],
		h.connID,
		data,
		h.scfg.Get(),
		certUncompressed,
		h.diversificationNonce,
	)
	if err != nil {
		return nil, err
	}

	// Generate a new curve instance to derive the forward secure key
	var fsNonce bytes.Buffer
	fsNonce.Write(cryptoData[TagNONC])
	fsNonce.Write(nonce)
	ephermalKex := h.keyExchange()
	ephermalSharedSecret, err := ephermalKex.CalculateSharedKey(cryptoData[TagPUBS])
	if err != nil {
		return nil, err
	}
	h.forwardSecureAEAD, err = h.keyDerivation(
		true,
		ephermalSharedSecret,
		fsNonce.Bytes(),
		h.connID,
		data,
		h.scfg.Get(),
		certUncompressed,
		nil,
	)
	if err != nil {
		return nil, err
	}

	err = h.connectionParametersManager.SetFromMap(cryptoData)
	if err != nil {
		return nil, err
	}

	replyMap := h.connectionParametersManager.GetSHLOMap()
	// add crypto parameters
	replyMap[TagPUBS] = ephermalKex.PublicKey()
	replyMap[TagSNO] = nonce
	replyMap[TagVER] = protocol.SupportedVersionsAsTags

	var reply bytes.Buffer
	WriteHandshakeMessage(&reply, TagSHLO, replyMap)

	h.aeadChanged <- struct{}{}

	return reply.Bytes(), nil
}

// DiversificationNonce returns a diversification nonce if required in the next packet to be Seal'ed. See LockForSealing()!
func (h *CryptoSetup) DiversificationNonce() []byte {
	if h.receivedForwardSecurePacket || h.secureAEAD == nil {
		return nil
	}
	return h.diversificationNonce
}

// LockForSealing should be called before Seal(). It is needed so that diversification nonces can be obtained before packets are sealed, and the AEADs are not changed in the meantime.
func (h *CryptoSetup) LockForSealing() {
	h.mutex.RLock()
}

// UnlockForSealing should be called after Seal() is complete, see LockForSealing().
func (h *CryptoSetup) UnlockForSealing() {
	h.mutex.RUnlock()
}

// HandshakeComplete returns true after the first forward secure packet was received form the client.
func (h *CryptoSetup) HandshakeComplete() bool {
	return h.receivedForwardSecurePacket
}
