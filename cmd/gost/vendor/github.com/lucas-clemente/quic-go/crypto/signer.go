package crypto

// A Signer holds a certificate and a private key
type Signer interface {
	SignServerProof(sni string, chlo []byte, serverConfigData []byte) ([]byte, error)
	GetCertsCompressed(sni string, commonSetHashes, cachedHashes []byte) ([]byte, error)
	GetLeafCert(sni string) ([]byte, error)
}
