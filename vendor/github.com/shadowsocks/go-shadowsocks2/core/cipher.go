package core

import (
	"crypto/md5"
	"errors"
	"net"
	"sort"
	"strings"

	"github.com/shadowsocks/go-shadowsocks2/shadowaead"
	"github.com/shadowsocks/go-shadowsocks2/shadowstream"
)

type Cipher interface {
	StreamConnCipher
	PacketConnCipher
}

type StreamConnCipher interface {
	StreamConn(net.Conn) net.Conn
}

type PacketConnCipher interface {
	PacketConn(net.PacketConn) net.PacketConn
}

// ErrCipherNotSupported occurs when a cipher is not supported (likely because of security concerns).
var ErrCipherNotSupported = errors.New("cipher not supported")

// List of AEAD ciphers: key size in bytes and constructor
var aeadList = map[string]struct {
	KeySize int
	New     func([]byte) (shadowaead.Cipher, error)
}{
	"AEAD_AES_128_GCM":       {16, shadowaead.AESGCM},
	"AEAD_AES_192_GCM":       {24, shadowaead.AESGCM},
	"AEAD_AES_256_GCM":       {32, shadowaead.AESGCM},
	"AEAD_CHACHA20_POLY1305": {32, shadowaead.Chacha20Poly1305},
}

// List of stream ciphers: key size in bytes and constructor
var streamList = map[string]struct {
	KeySize int
	New     func(key []byte) (shadowstream.Cipher, error)
}{
	"AES-128-CTR":   {16, shadowstream.AESCTR},
	"AES-192-CTR":   {24, shadowstream.AESCTR},
	"AES-256-CTR":   {32, shadowstream.AESCTR},
	"AES-128-CFB":   {16, shadowstream.AESCFB},
	"AES-192-CFB":   {24, shadowstream.AESCFB},
	"AES-256-CFB":   {32, shadowstream.AESCFB},
	"CHACHA20-IETF": {32, shadowstream.Chacha20IETF},
	"XCHACHA20":     {32, shadowstream.Xchacha20},
}

// ListCipher returns a list of available cipher names sorted alphabetically.
func ListCipher() []string {
	var l []string
	for k := range aeadList {
		l = append(l, k)
	}
	for k := range streamList {
		l = append(l, k)
	}
	sort.Strings(l)
	return l
}

// PickCipher returns a Cipher of the given name. Derive key from password if given key is empty.
func PickCipher(name string, key []byte, password string) (Cipher, error) {
	name = strings.ToUpper(name)

	switch name {
	case "DUMMY":
		return &dummy{}, nil
	case "CHACHA20-IETF-POLY1305":
		name = "AEAD_CHACHA20_POLY1305"
	case "AES-128-GCM":
		name = "AEAD_AES_128_GCM"
	case "AES-196-GCM":
		name = "AEAD_AES_196_GCM"
	case "AES-256-GCM":
		name = "AEAD_AES_256_GCM"
	}

	if choice, ok := aeadList[name]; ok {
		if len(key) == 0 {
			key = kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, shadowaead.KeySizeError(choice.KeySize)
		}
		aead, err := choice.New(key)
		return &aeadCipher{aead}, err
	}

	if choice, ok := streamList[name]; ok {
		if len(key) == 0 {
			key = kdf(password, choice.KeySize)
		}
		if len(key) != choice.KeySize {
			return nil, shadowstream.KeySizeError(choice.KeySize)
		}
		ciph, err := choice.New(key)
		return &streamCipher{ciph}, err
	}

	return nil, ErrCipherNotSupported
}

type aeadCipher struct{ shadowaead.Cipher }

func (aead *aeadCipher) StreamConn(c net.Conn) net.Conn { return shadowaead.NewConn(c, aead) }
func (aead *aeadCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return shadowaead.NewPacketConn(c, aead)
}

type streamCipher struct{ shadowstream.Cipher }

func (ciph *streamCipher) StreamConn(c net.Conn) net.Conn { return shadowstream.NewConn(c, ciph) }
func (ciph *streamCipher) PacketConn(c net.PacketConn) net.PacketConn {
	return shadowstream.NewPacketConn(c, ciph)
}

// dummy cipher does not encrypt

type dummy struct{}

func (dummy) StreamConn(c net.Conn) net.Conn             { return c }
func (dummy) PacketConn(c net.PacketConn) net.PacketConn { return c }

// key-derivation function from original Shadowsocks
func kdf(password string, keyLen int) []byte {
	var b, prev []byte
	h := md5.New()
	for len(b) < keyLen {
		h.Write(prev)
		h.Write([]byte(password))
		b = h.Sum(b)
		prev = b[len(b)-h.Size():]
		h.Reset()
	}
	return b[:keyLen]
}
