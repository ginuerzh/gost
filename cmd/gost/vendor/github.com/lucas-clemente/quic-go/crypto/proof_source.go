package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"strings"
)

// proofSource stores a key and a certificate for the server proof
type proofSource struct {
	config *tls.Config
}

// NewProofSource loads the key and cert from files
func NewProofSource(tlsConfig *tls.Config) (Signer, error) {
	return &proofSource{config: tlsConfig}, nil
}

// SignServerProof signs CHLO and server config for use in the server proof
func (ps *proofSource) SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error) {
	cert, err := ps.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}

	hash := sha256.New()
	hash.Write([]byte("QUIC CHLO and server config signature\x00"))
	chloHash := sha256.Sum256(chlo)
	hash.Write([]byte{32, 0, 0, 0})
	hash.Write(chloHash[:])
	hash.Write(serverConfigData)

	key, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("expected PrivateKey to implement crypto.Signer")
	}

	opts := crypto.SignerOpts(crypto.SHA256)

	if _, ok = key.(*rsa.PrivateKey); ok {
		opts = &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}
	}

	return key.Sign(rand.Reader, hash.Sum(nil), opts)
}

// GetCertsCompressed gets the certificate in the format described by the QUIC crypto doc
func (ps *proofSource) GetCertsCompressed(sni string, pCommonSetHashes, pCachedHashes []byte) ([]byte, error) {
	cert, err := ps.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}
	return getCompressedCert(cert.Certificate, pCommonSetHashes, pCachedHashes)
}

// GetLeafCert gets the leaf certificate
func (ps *proofSource) GetLeafCert(sni string) ([]byte, error) {
	cert, err := ps.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}
	return cert.Certificate[0], nil
}

func (ps *proofSource) getCertForSNI(sni string) (*tls.Certificate, error) {
	if ps.config.GetCertificate != nil {
		cert, err := ps.config.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			return nil, err
		}
		if cert != nil {
			return cert, nil
		}
	}
	if len(ps.config.NameToCertificate) != 0 {
		if cert, ok := ps.config.NameToCertificate[sni]; ok {
			return cert, nil
		}
		wildcardSNI := "*" + strings.TrimLeftFunc(sni, func(r rune) bool { return r != '.' })
		if cert, ok := ps.config.NameToCertificate[wildcardSNI]; ok {
			return cert, nil
		}
	}
	if len(ps.config.Certificates) != 0 {
		return &ps.config.Certificates[0], nil
	}
	return nil, errors.New("no matching certificate found")
}
