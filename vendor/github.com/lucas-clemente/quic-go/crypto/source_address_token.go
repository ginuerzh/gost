package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/lucas-clemente/quic-go/protocol"

	"golang.org/x/crypto/hkdf"
)

// StkSource is used to create and verify source address tokens
type StkSource interface {
	// NewToken creates a new token for a given IP address
	NewToken(ip net.IP) ([]byte, error)
	// VerifyToken verifies if a token matches a given IP address and is not outdated
	VerifyToken(ip net.IP, data []byte) error
}

type sourceAddressToken struct {
	ip net.IP
	// unix timestamp in seconds
	timestamp uint64
}

func (t *sourceAddressToken) serialize() []byte {
	res := make([]byte, 8+len(t.ip))
	binary.LittleEndian.PutUint64(res, t.timestamp)
	copy(res[8:], t.ip)
	return res
}

func parseToken(data []byte) (*sourceAddressToken, error) {
	if len(data) != 8+4 && len(data) != 8+16 {
		return nil, fmt.Errorf("invalid STK length: %d", len(data))
	}
	return &sourceAddressToken{
		ip:        data[8:],
		timestamp: binary.LittleEndian.Uint64(data),
	}, nil
}

type stkSource struct {
	aead cipher.AEAD
}

const stkKeySize = 16

// Chrome currently sets this to 12, but discusses changing it to 16. We start
// at 16 :)
const stkNonceSize = 16

// NewStkSource creates a source for source address tokens
func NewStkSource(secret []byte) (StkSource, error) {
	key, err := deriveKey(secret)
	if err != nil {
		return nil, err
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(c, stkNonceSize)
	if err != nil {
		return nil, err
	}
	return &stkSource{aead: aead}, nil
}

func (s *stkSource) NewToken(ip net.IP) ([]byte, error) {
	return encryptToken(s.aead, &sourceAddressToken{
		ip:        ip,
		timestamp: uint64(time.Now().Unix()),
	})
}

func (s *stkSource) VerifyToken(ip net.IP, data []byte) error {
	if len(data) < stkNonceSize {
		return errors.New("STK too short")
	}
	nonce := data[:stkNonceSize]

	res, err := s.aead.Open(nil, nonce, data[stkNonceSize:], nil)
	if err != nil {
		return err
	}

	token, err := parseToken(res)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(token.ip, ip) != 1 {
		return errors.New("invalid ip in STK")
	}

	if time.Now().Unix() > int64(token.timestamp)+protocol.STKExpiryTimeSec {
		return errors.New("STK expired")
	}

	return nil
}

func deriveKey(secret []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, secret, nil, []byte("QUIC source address token key"))
	key := make([]byte, stkKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

func encryptToken(aead cipher.AEAD, token *sourceAddressToken) ([]byte, error) {
	nonce := make([]byte, stkNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, token.serialize(), nil), nil
}
