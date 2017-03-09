package crypto

import (
	"crypto/tls"
	"errors"
	"strings"
)

// A CertChain holds a certificate and a private key
type CertChain interface {
	SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error)
	GetCertsCompressed(sni string, commonSetHashes, cachedHashes []byte) ([]byte, error)
	GetLeafCert(sni string) ([]byte, error)
}

// proofSource stores a key and a certificate for the server proof
type certChain struct {
	config *tls.Config
}

var _ CertChain = &certChain{}

var errNoMatchingCertificate = errors.New("no matching certificate found")

// NewCertChain loads the key and cert from files
func NewCertChain(tlsConfig *tls.Config) CertChain {
	return &certChain{config: tlsConfig}
}

// SignServerProof signs CHLO and server config for use in the server proof
func (c *certChain) SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error) {
	cert, err := c.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}

	return signServerProof(cert, chlo, serverConfigData)
}

// GetCertsCompressed gets the certificate in the format described by the QUIC crypto doc
func (c *certChain) GetCertsCompressed(sni string, pCommonSetHashes, pCachedHashes []byte) ([]byte, error) {
	cert, err := c.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}
	return getCompressedCert(cert.Certificate, pCommonSetHashes, pCachedHashes)
}

// GetLeafCert gets the leaf certificate
func (c *certChain) GetLeafCert(sni string) ([]byte, error) {
	cert, err := c.getCertForSNI(sni)
	if err != nil {
		return nil, err
	}
	return cert.Certificate[0], nil
}

func (c *certChain) getCertForSNI(sni string) (*tls.Certificate, error) {
	if c.config.GetCertificate != nil {
		cert, err := c.config.GetCertificate(&tls.ClientHelloInfo{ServerName: sni})
		if err != nil {
			return nil, err
		}
		if cert != nil {
			return cert, nil
		}
	}

	if len(c.config.NameToCertificate) != 0 {
		if cert, ok := c.config.NameToCertificate[sni]; ok {
			return cert, nil
		}
		wildcardSNI := "*" + strings.TrimLeftFunc(sni, func(r rune) bool { return r != '.' })
		if cert, ok := c.config.NameToCertificate[wildcardSNI]; ok {
			return cert, nil
		}
	}

	if len(c.config.Certificates) != 0 {
		return &c.config.Certificates[0], nil
	}

	return nil, errNoMatchingCertificate
}
