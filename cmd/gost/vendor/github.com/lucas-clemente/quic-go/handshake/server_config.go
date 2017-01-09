package handshake

import (
	"bytes"
	"crypto/rand"

	"github.com/lucas-clemente/quic-go/crypto"
)

// ServerConfig is a server config
type ServerConfig struct {
	kex       crypto.KeyExchange
	signer    crypto.Signer
	ID        []byte
	stkSource crypto.StkSource
}

// NewServerConfig creates a new server config
func NewServerConfig(kex crypto.KeyExchange, signer crypto.Signer) (*ServerConfig, error) {
	id := make([]byte, 16)
	_, err := rand.Read(id)
	if err != nil {
		return nil, err
	}

	stkSecret := make([]byte, 32)
	if _, err = rand.Read(stkSecret); err != nil {
		return nil, err
	}
	stkSource, err := crypto.NewStkSource(stkSecret)
	if err != nil {
		return nil, err
	}

	return &ServerConfig{
		kex:       kex,
		signer:    signer,
		ID:        id,
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
		TagOBIT: {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7},
		TagEXPY: {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	})
	return serverConfig.Bytes()
}

// Sign the server config and CHLO with the server's keyData
func (s *ServerConfig) Sign(sni string, chlo []byte) ([]byte, error) {
	return s.signer.SignServerProof(sni, chlo, s.Get())
}

// GetCertsCompressed returns the certificate data
func (s *ServerConfig) GetCertsCompressed(sni string, commonSetHashes, compressedHashes []byte) ([]byte, error) {
	return s.signer.GetCertsCompressed(sni, commonSetHashes, compressedHashes)
}
