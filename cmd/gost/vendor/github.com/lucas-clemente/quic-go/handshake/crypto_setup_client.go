package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go/crypto"
	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/qerr"
	"github.com/lucas-clemente/quic-go/utils"
)

type cryptoSetupClient struct {
	mutex sync.RWMutex

	hostname           string
	connID             protocol.ConnectionID
	version            protocol.VersionNumber
	negotiatedVersions []protocol.VersionNumber

	cryptoStream utils.Stream

	serverConfig *serverConfigClient

	stk                  []byte
	sno                  []byte
	nonc                 []byte
	proof                []byte
	diversificationNonce []byte
	chloForSignature     []byte
	lastSentCHLO         []byte
	certManager          crypto.CertManager

	clientHelloCounter int
	serverVerified     bool // has the certificate chain and the proof already been verified
	keyDerivation      KeyDerivationFunction

	receivedSecurePacket bool
	secureAEAD           crypto.AEAD
	forwardSecureAEAD    crypto.AEAD
	aeadChanged          chan struct{}

	connectionParameters ConnectionParametersManager
}

var _ crypto.AEAD = &cryptoSetupClient{}
var _ CryptoSetup = &cryptoSetupClient{}

var (
	errNoObitForClientNonce             = errors.New("CryptoSetup BUG: No OBIT for client nonce available")
	errClientNonceAlreadyExists         = errors.New("CryptoSetup BUG: A client nonce was already generated")
	errConflictingDiversificationNonces = errors.New("Received two different diversification nonces")
)

// NewCryptoSetupClient creates a new CryptoSetup instance for a client
func NewCryptoSetupClient(
	hostname string,
	connID protocol.ConnectionID,
	version protocol.VersionNumber,
	cryptoStream utils.Stream,
	tlsConfig *tls.Config,
	connectionParameters ConnectionParametersManager,
	aeadChanged chan struct{},
	negotiatedVersions []protocol.VersionNumber,
) (CryptoSetup, error) {
	return &cryptoSetupClient{
		hostname:             hostname,
		connID:               connID,
		version:              version,
		cryptoStream:         cryptoStream,
		certManager:          crypto.NewCertManager(tlsConfig),
		connectionParameters: connectionParameters,
		keyDerivation:        crypto.DeriveKeysAESGCM,
		aeadChanged:          aeadChanged,
		negotiatedVersions:   negotiatedVersions,
	}, nil
}

func (h *cryptoSetupClient) HandleCryptoStream() error {
	for {
		err := h.maybeUpgradeCrypto()
		if err != nil {
			return err
		}

		// send CHLOs until the forward secure encryption is established
		if h.forwardSecureAEAD == nil {
			err = h.sendCHLO()
			if err != nil {
				return err
			}
		}

		var shloData bytes.Buffer

		messageTag, cryptoData, err := ParseHandshakeMessage(io.TeeReader(h.cryptoStream, &shloData))
		if err != nil {
			return qerr.HandshakeFailed
		}

		if messageTag != TagSHLO && messageTag != TagREJ {
			return qerr.InvalidCryptoMessageType
		}

		if messageTag == TagSHLO {
			utils.Debugf("Got SHLO:\n%s", printHandshakeMessage(cryptoData))
			err = h.handleSHLOMessage(cryptoData)
			if err != nil {
				return err
			}
		}

		if messageTag == TagREJ {
			err = h.handleREJMessage(cryptoData)
			if err != nil {
				return err
			}
		}
	}
}

func (h *cryptoSetupClient) handleREJMessage(cryptoData map[Tag][]byte) error {
	utils.Debugf("Got REJ:\n%s", printHandshakeMessage(cryptoData))

	var err error

	if stk, ok := cryptoData[TagSTK]; ok {
		h.stk = stk
	}

	if sno, ok := cryptoData[TagSNO]; ok {
		h.sno = sno
	}

	// TODO: what happens if the server sends a different server config in two packets?
	if scfg, ok := cryptoData[TagSCFG]; ok {
		h.serverConfig, err = parseServerConfig(scfg)
		if err != nil {
			return err
		}

		if h.serverConfig.IsExpired() {
			return qerr.CryptoServerConfigExpired
		}

		// now that we have a server config, we can use its OBIT value to generate a client nonce
		if len(h.nonc) == 0 {
			err = h.generateClientNonce()
			if err != nil {
				return err
			}
		}
	}

	if proof, ok := cryptoData[TagPROF]; ok {
		h.proof = proof
		h.chloForSignature = h.lastSentCHLO
	}

	if crt, ok := cryptoData[TagCERT]; ok {
		err := h.certManager.SetData(crt)
		if err != nil {
			return qerr.Error(qerr.InvalidCryptoMessageParameter, "Certificate data invalid")
		}

		err = h.certManager.Verify(h.hostname)
		if err != nil {
			utils.Infof("Certificate validation failed: %s", err.Error())
			return qerr.ProofInvalid
		}
	}

	if h.serverConfig != nil && len(h.proof) != 0 && h.certManager.GetLeafCert() != nil {
		validProof := h.certManager.VerifyServerProof(h.proof, h.chloForSignature, h.serverConfig.Get())
		if !validProof {
			utils.Infof("Server proof verification failed")
			return qerr.ProofInvalid
		}

		h.serverVerified = true
	}

	return nil
}

func (h *cryptoSetupClient) handleSHLOMessage(cryptoData map[Tag][]byte) error {
	h.mutex.Lock()
	defer h.mutex.Unlock()

	if !h.receivedSecurePacket {
		return qerr.Error(qerr.CryptoEncryptionLevelIncorrect, "unencrypted SHLO message")
	}

	if sno, ok := cryptoData[TagSNO]; ok {
		h.sno = sno
	}

	serverPubs, ok := cryptoData[TagPUBS]
	if !ok {
		return qerr.Error(qerr.CryptoMessageParameterNotFound, "PUBS")
	}

	verTag, ok := cryptoData[TagVER]
	if !ok {
		return qerr.Error(qerr.InvalidCryptoMessageParameter, "server hello missing version list")
	}
	if !h.validateVersionList(verTag) {
		return qerr.Error(qerr.VersionNegotiationMismatch, "Downgrade attack detected")
	}

	nonce := append(h.nonc, h.sno...)

	ephermalSharedSecret, err := h.serverConfig.kex.CalculateSharedKey(serverPubs)
	if err != nil {
		return err
	}

	leafCert := h.certManager.GetLeafCert()

	h.forwardSecureAEAD, err = h.keyDerivation(
		true,
		ephermalSharedSecret,
		nonce,
		h.connID,
		h.lastSentCHLO,
		h.serverConfig.Get(),
		leafCert,
		nil,
		protocol.PerspectiveClient,
	)
	if err != nil {
		return err
	}

	err = h.connectionParameters.SetFromMap(cryptoData)
	if err != nil {
		return qerr.InvalidCryptoMessageParameter
	}

	h.aeadChanged <- struct{}{}

	return nil
}

func (h *cryptoSetupClient) validateVersionList(verTags []byte) bool {
	if len(h.negotiatedVersions) == 0 {
		return true
	}
	if len(verTags)%4 != 0 || len(verTags)/4 != len(h.negotiatedVersions) {
		return false
	}

	b := bytes.NewReader(verTags)
	for _, negotiatedVersion := range h.negotiatedVersions {
		verTag, err := utils.ReadUint32(b)
		if err != nil { // should never occur, since the length was already checked
			return false
		}
		ver := protocol.VersionTagToNumber(verTag)
		if !protocol.IsSupportedVersion(ver) {
			ver = protocol.VersionUnsupported
		}
		if ver != negotiatedVersion {
			return false
		}
	}
	return true
}

func (h *cryptoSetupClient) Open(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) ([]byte, error) {
	if h.forwardSecureAEAD != nil {
		data, err := h.forwardSecureAEAD.Open(dst, src, packetNumber, associatedData)
		if err == nil {
			return data, nil
		}
		return nil, err
	}

	if h.secureAEAD != nil {
		data, err := h.secureAEAD.Open(dst, src, packetNumber, associatedData)
		if err == nil {
			h.receivedSecurePacket = true
			return data, nil
		}
		if h.receivedSecurePacket {
			return nil, err
		}
	}

	return (&crypto.NullAEAD{}).Open(dst, src, packetNumber, associatedData)
}

func (h *cryptoSetupClient) Seal(dst, src []byte, packetNumber protocol.PacketNumber, associatedData []byte) []byte {
	if h.forwardSecureAEAD != nil {
		return h.forwardSecureAEAD.Seal(dst, src, packetNumber, associatedData)
	}
	if h.secureAEAD != nil {
		return h.secureAEAD.Seal(dst, src, packetNumber, associatedData)
	}
	return (&crypto.NullAEAD{}).Seal(dst, src, packetNumber, associatedData)
}

func (h *cryptoSetupClient) DiversificationNonce() []byte {
	panic("not needed for cryptoSetupClient")
}

func (h *cryptoSetupClient) SetDiversificationNonce(data []byte) error {
	if len(h.diversificationNonce) == 0 {
		h.diversificationNonce = data
		return h.maybeUpgradeCrypto()
	}
	if !bytes.Equal(h.diversificationNonce, data) {
		return errConflictingDiversificationNonces
	}
	return nil
}

func (h *cryptoSetupClient) LockForSealing() {

}

func (h *cryptoSetupClient) UnlockForSealing() {

}

func (h *cryptoSetupClient) HandshakeComplete() bool {
	h.mutex.RLock()
	complete := h.forwardSecureAEAD != nil
	h.mutex.RUnlock()
	return complete
}

func (h *cryptoSetupClient) sendCHLO() error {
	h.clientHelloCounter++
	if h.clientHelloCounter > protocol.MaxClientHellos {
		return qerr.Error(qerr.CryptoTooManyRejects, fmt.Sprintf("More than %d rejects", protocol.MaxClientHellos))
	}

	b := &bytes.Buffer{}

	tags, err := h.getTags()
	if err != nil {
		return err
	}
	h.addPadding(tags)

	utils.Debugf("Sending CHLO:\n%s", printHandshakeMessage(tags))
	WriteHandshakeMessage(b, TagCHLO, tags)

	_, err = h.cryptoStream.Write(b.Bytes())
	if err != nil {
		return err
	}

	h.lastSentCHLO = b.Bytes()

	return nil
}

func (h *cryptoSetupClient) getTags() (map[Tag][]byte, error) {
	tags, err := h.connectionParameters.GetHelloMap()
	if err != nil {
		return nil, err
	}
	tags[TagSNI] = []byte(h.hostname)
	tags[TagPDMD] = []byte("X509")

	ccs := h.certManager.GetCommonCertificateHashes()
	if len(ccs) > 0 {
		tags[TagCCS] = ccs
	}

	versionTag := make([]byte, 4, 4)
	binary.LittleEndian.PutUint32(versionTag, protocol.VersionNumberToTag(h.version))
	tags[TagVER] = versionTag

	if len(h.stk) > 0 {
		tags[TagSTK] = h.stk
	}

	if len(h.sno) > 0 {
		tags[TagSNO] = h.sno
	}

	if h.serverConfig != nil {
		tags[TagSCID] = h.serverConfig.ID

		leafCert := h.certManager.GetLeafCert()
		if leafCert != nil {
			certHash, _ := h.certManager.GetLeafCertHash()
			xlct := make([]byte, 8, 8)
			binary.LittleEndian.PutUint64(xlct, certHash)

			tags[TagNONC] = h.nonc
			tags[TagXLCT] = xlct
			tags[TagKEXS] = []byte("C255")
			tags[TagAEAD] = []byte("AESG")
			tags[TagPUBS] = h.serverConfig.kex.PublicKey() // TODO: check if 3 bytes need to be prepended
		}
	}

	return tags, nil
}

// add a TagPAD to a tagMap, such that the total size will be bigger than the ClientHelloMinimumSize
func (h *cryptoSetupClient) addPadding(tags map[Tag][]byte) {
	var size int
	for _, tag := range tags {
		size += 8 + len(tag) // 4 bytes for the tag + 4 bytes for the offset + the length of the data
	}
	paddingSize := protocol.ClientHelloMinimumSize - size
	if paddingSize > 0 {
		tags[TagPAD] = bytes.Repeat([]byte{0}, paddingSize)
	}
}

func (h *cryptoSetupClient) maybeUpgradeCrypto() error {
	if !h.serverVerified {
		return nil
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	leafCert := h.certManager.GetLeafCert()

	if h.secureAEAD == nil && (h.serverConfig != nil && len(h.serverConfig.sharedSecret) > 0 && len(h.nonc) > 0 && len(leafCert) > 0 && len(h.diversificationNonce) > 0 && len(h.lastSentCHLO) > 0) {
		var err error
		var nonce []byte
		if h.sno == nil {
			nonce = h.nonc
		} else {
			nonce = append(h.nonc, h.sno...)
		}

		h.secureAEAD, err = h.keyDerivation(
			false,
			h.serverConfig.sharedSecret,
			nonce,
			h.connID,
			h.lastSentCHLO,
			h.serverConfig.Get(),
			leafCert,
			h.diversificationNonce,
			protocol.PerspectiveClient,
		)
		if err != nil {
			return err
		}

		h.aeadChanged <- struct{}{}
	}

	return nil
}

func (h *cryptoSetupClient) generateClientNonce() error {
	if len(h.nonc) > 0 {
		return errClientNonceAlreadyExists
	}

	nonc := make([]byte, 32)
	binary.BigEndian.PutUint32(nonc, uint32(time.Now().Unix()))

	if len(h.serverConfig.obit) != 8 {
		return errNoObitForClientNonce
	}

	copy(nonc[4:12], h.serverConfig.obit)

	_, err := rand.Read(nonc[12:])
	if err != nil {
		return err
	}

	h.nonc = nonc
	return nil
}
