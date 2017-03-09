package handshake

import (
	"bytes"
	"crypto/rand"

	"github.com/lucas-clemente/quic-go/crypto"
)

// ServerConfig is a server config
type ServerConfig struct {
	kex       crypto.KeyExchange
	certChain crypto.CertChain
	ID        []byte
	obit      []byte
	stkSource crypto.StkSource
}

// NewServerConfig creates a new server config
func NewServerConfig(kex crypto.KeyExchange, certChain crypto.CertChain) (*ServerConfig, error) {
	id := make([]byte, 16)
	_, err := rand.Read(id)
	if err != nil {
		return nil, err
	}

	stkSecret := make([]byte, 32)
	if _, err = rand.Read(stkSecret); err != nil {
		return nil, err
	}

	obit := make([]byte, 8)
	if _, err = rand.Read(obit); err != nil {
		return nil, err
	}

	stkSource, err := crypto.NewStkSource(stkSecret)
	if err != nil {
		return nil, err
	}

	return &ServerConfig{
		kex:       kex,
		certChain: certChain,
		ID:        id,
		obit:      obit,
		stkSource: stkSource,
	}, nil
}

// Get the server config binary representation
func (s *ServerConfig) Get() []byte {
	var serverConfig bytes.Buffer
	WriteHandshakeMessage(&serverConfig, TagSCFG, map[Tag][]byte{
		TagSCID: s.ID,
		TagKEXS: []byte("C255"),
		TagAEAD: []byte("AESG"),
		TagPUBS: append([]byte{0x20, 0x00, 0x00}, s.kex.PublicKey()...),
		TagOBIT: s.obit,
		TagEXPY: {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	})
	return serverConfig.Bytes()
}

// Sign the server config and CHLO with the server's keyData
func (s *ServerConfig) Sign(sni string, chlo []byte) ([]byte, error) {
	return s.certChain.SignServerProof(sni, chlo, s.Get())
}

// GetCertsCompressed returns the certificate data
func (s *ServerConfig) GetCertsCompressed(sni string, commonSetHashes, compressedHashes []byte) ([]byte, error) {
	return s.certChain.GetCertsCompressed(sni, commonSetHashes, compressedHashes)
}
