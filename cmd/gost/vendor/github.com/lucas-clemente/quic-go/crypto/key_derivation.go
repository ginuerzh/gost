package crypto

import (
	"bytes"
	"crypto/sha256"
	"io"

	"github.com/lucas-clemente/quic-go/protocol"
	"github.com/lucas-clemente/quic-go/utils"

	"golang.org/x/crypto/hkdf"
)

// DeriveKeysChacha20 derives the client and server keys and creates a matching chacha20poly1305 AEAD instance
// func DeriveKeysChacha20(version protocol.VersionNumber, forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte) (AEAD, error) {
// 	otherKey, myKey, otherIV, myIV, err := deriveKeys(version, forwardSecure, sharedSecret, nonces, connID, chlo, scfg, cert, divNonce, 32)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return NewAEADChacha20Poly1305(otherKey, myKey, otherIV, myIV)
// }

// DeriveKeysAESGCM derives the client and server keys and creates a matching AES-GCM AEAD instance
func DeriveKeysAESGCM(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo []byte, scfg []byte, cert []byte, divNonce []byte) (AEAD, error) {
	otherKey, myKey, otherIV, myIV, err := deriveKeys(forwardSecure, sharedSecret, nonces, connID, chlo, scfg, cert, divNonce, 16)
	if err != nil {
		return nil, err
	}
	return NewAEADAESGCM(otherKey, myKey, otherIV, myIV)
}

func deriveKeys(forwardSecure bool, sharedSecret, nonces []byte, connID protocol.ConnectionID, chlo, scfg, cert, divNonce []byte, keyLen int) ([]byte, []byte, []byte, []byte, error) {
	var info bytes.Buffer
	if forwardSecure {
		info.Write([]byte("QUIC forward secure key expansion\x00"))
	} else {
		info.Write([]byte("QUIC key expansion\x00"))
	}
	utils.WriteUint64(&info, uint64(connID))
	info.Write(chlo)
	info.Write(scfg)
	info.Write(cert)

	r := hkdf.New(sha256.New, sharedSecret, nonces, info.Bytes())

	s := make([]byte, 2*keyLen+2*4)
	if _, err := io.ReadFull(r, s); err != nil {
		return nil, nil, nil, nil, err
	}
	otherKey := s[:keyLen]
	myKey := s[keyLen : 2*keyLen]
	otherIV := s[2*keyLen : 2*keyLen+4]
	myIV := s[2*keyLen+4:]

	if !forwardSecure {
		if err := diversify(myKey, myIV, divNonce); err != nil {
			return nil, nil, nil, nil, err
		}
	}

	return otherKey, myKey, otherIV, myIV, nil
}

func diversify(key, iv, divNonce []byte) error {
	secret := make([]byte, len(key)+len(iv))
	copy(secret, key)
	copy(secret[len(key):], iv)

	r := hkdf.New(sha256.New, secret, divNonce, []byte("QUIC key diversification"))

	if _, err := io.ReadFull(r, key); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, iv); err != nil {
		return err
	}

	return nil
}
