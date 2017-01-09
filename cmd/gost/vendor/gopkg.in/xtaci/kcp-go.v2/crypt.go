package kcp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/tea"
	"golang.org/x/crypto/twofish"
	"golang.org/x/crypto/xtea"
)

var (
	initialVector = []byte{167, 115, 79, 156, 18, 172, 27, 1, 164, 21, 242, 193, 252, 120, 230, 107}
	saltxor       = `sH3CIVoF#rWLtJo6`
)

// BlockCrypt defines encryption/decryption methods for a given byte slice
type BlockCrypt interface {
	// Encrypt encrypts the whole block in src into dst.
	// Dst and src may point at the same memory.
	Encrypt(dst, src []byte)

	// Decrypt decrypts the whole block in src into dst.
	// Dst and src may point at the same memory.
	Decrypt(dst, src []byte)
}

// Salsa20BlockCrypt implements BlockCrypt
type Salsa20BlockCrypt struct {
	key [32]byte
}

// NewSalsa20BlockCrypt initates BlockCrypt by the given key
func NewSalsa20BlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(Salsa20BlockCrypt)
	copy(c.key[:], key)
	return c, nil
}

// Encrypt implements Encrypt interface
func (c *Salsa20BlockCrypt) Encrypt(dst, src []byte) {
	salsa20.XORKeyStream(dst[8:], src[8:], src[:8], &c.key)
	copy(dst[:8], src[:8])
}

// Decrypt implements Decrypt interface
func (c *Salsa20BlockCrypt) Decrypt(dst, src []byte) {
	salsa20.XORKeyStream(dst[8:], src[8:], src[:8], &c.key)
	copy(dst[:8], src[:8])
}

// TwofishBlockCrypt implements BlockCrypt
type TwofishBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewTwofishBlockCrypt initates BlockCrypt by the given key
func NewTwofishBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(TwofishBlockCrypt)
	block, err := twofish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, twofish.BlockSize)
	c.decbuf = make([]byte, 2*twofish.BlockSize)
	return c, nil
}

// Encrypt implements Encrypt interface
func (c *TwofishBlockCrypt) Encrypt(dst, src []byte) { encrypt(c.block, dst, src, c.encbuf) }

// Decrypt implements Decrypt interface
func (c *TwofishBlockCrypt) Decrypt(dst, src []byte) { decrypt(c.block, dst, src, c.decbuf) }

// TripleDESBlockCrypt implements BlockCrypt
type TripleDESBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewTripleDESBlockCrypt initates BlockCrypt by the given key
func NewTripleDESBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(TripleDESBlockCrypt)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, des.BlockSize)
	c.decbuf = make([]byte, 2*des.BlockSize)
	return c, nil
}

// Encrypt implements Encrypt interface
func (c *TripleDESBlockCrypt) Encrypt(dst, src []byte) { encrypt(c.block, dst, src, c.encbuf) }

// Decrypt implements Decrypt interface
func (c *TripleDESBlockCrypt) Decrypt(dst, src []byte) { decrypt(c.block, dst, src, c.decbuf) }

// Cast5BlockCrypt implements BlockCrypt
type Cast5BlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewCast5BlockCrypt initates BlockCrypt by the given key
func NewCast5BlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(Cast5BlockCrypt)
	block, err := cast5.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, cast5.BlockSize)
	c.decbuf = make([]byte, 2*cast5.BlockSize)
	return c, nil
}

// Encrypt implements Encrypt interface
func (c *Cast5BlockCrypt) Encrypt(dst, src []byte) { encrypt(c.block, dst, src, c.encbuf) }

// Decrypt implements Decrypt interface
func (c *Cast5BlockCrypt) Decrypt(dst, src []byte) { decrypt(c.block, dst, src, c.decbuf) }

// BlowfishBlockCrypt implements BlockCrypt
type BlowfishBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewBlowfishBlockCrypt initates BlockCrypt by the given key
func NewBlowfishBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(BlowfishBlockCrypt)
	block, err := blowfish.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, blowfish.BlockSize)
	c.decbuf = make([]byte, 2*blowfish.BlockSize)
	return c, nil
}

// Encrypt implements Encrypt interface
func (c *BlowfishBlockCrypt) Encrypt(dst, src []byte) { encrypt(c.block, dst, src, c.encbuf) }

// Decrypt implements Decrypt interface
func (c *BlowfishBlockCrypt) Decrypt(dst, src []byte) { decrypt(c.block, dst, src, c.decbuf) }

// AESBlockCrypt implements BlockCrypt
type AESBlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewAESBlockCrypt initates BlockCrypt by the given key
func NewAESBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(AESBlockCrypt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, aes.BlockSize)
	c.decbuf = make([]byte, 2*aes.BlockSize)
	return c, nil
}

// Encrypt implements Encrypt interface
func (c *AESBlockCrypt) Encrypt(dst, src []byte) { encrypt(c.block, dst, src, c.encbuf) }

// Decrypt implements Decrypt interface
func (c *AESBlockCrypt) Decrypt(dst, src []byte) { decrypt(c.block, dst, src, c.decbuf) }

// TEABlockCrypt implements BlockCrypt
type TEABlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewTEABlockCrypt initate BlockCrypt by the given key
func NewTEABlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(TEABlockCrypt)
	block, err := tea.NewCipherWithRounds(key, 16)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, tea.BlockSize)
	c.decbuf = make([]byte, 2*tea.BlockSize)
	return c, nil
}

// Encrypt implements Encrypt interface
func (c *TEABlockCrypt) Encrypt(dst, src []byte) { encrypt(c.block, dst, src, c.encbuf) }

// Decrypt implements Decrypt interface
func (c *TEABlockCrypt) Decrypt(dst, src []byte) { decrypt(c.block, dst, src, c.decbuf) }

// XTEABlockCrypt implements BlockCrypt
type XTEABlockCrypt struct {
	encbuf []byte
	decbuf []byte
	block  cipher.Block
}

// NewXTEABlockCrypt initate BlockCrypt by the given key
func NewXTEABlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(XTEABlockCrypt)
	block, err := xtea.NewCipher(key)
	if err != nil {
		return nil, err
	}
	c.block = block
	c.encbuf = make([]byte, xtea.BlockSize)
	c.decbuf = make([]byte, 2*xtea.BlockSize)
	return c, nil
}

// Encrypt implements Encrypt interface
func (c *XTEABlockCrypt) Encrypt(dst, src []byte) { encrypt(c.block, dst, src, c.encbuf) }

// Decrypt implements Decrypt interface
func (c *XTEABlockCrypt) Decrypt(dst, src []byte) { decrypt(c.block, dst, src, c.decbuf) }

// SimpleXORBlockCrypt implements BlockCrypt
type SimpleXORBlockCrypt struct {
	xortbl []byte
}

// NewSimpleXORBlockCrypt initate BlockCrypt by the given key
func NewSimpleXORBlockCrypt(key []byte) (BlockCrypt, error) {
	c := new(SimpleXORBlockCrypt)
	c.xortbl = pbkdf2.Key(key, []byte(saltxor), 32, mtuLimit, sha1.New)
	return c, nil
}

// Encrypt implements Encrypt interface
func (c *SimpleXORBlockCrypt) Encrypt(dst, src []byte) { xorBytes(dst, src, c.xortbl) }

// Decrypt implements Decrypt interface
func (c *SimpleXORBlockCrypt) Decrypt(dst, src []byte) { xorBytes(dst, src, c.xortbl) }

// NoneBlockCrypt simple returns the plaintext
type NoneBlockCrypt struct{}

// NewNoneBlockCrypt initate by the given key
func NewNoneBlockCrypt(key []byte) (BlockCrypt, error) {
	return new(NoneBlockCrypt), nil
}

// Encrypt implements Encrypt interface
func (c *NoneBlockCrypt) Encrypt(dst, src []byte) { copy(dst, src) }

// Decrypt implements Decrypt interface
func (c *NoneBlockCrypt) Decrypt(dst, src []byte) { copy(dst, src) }

// packet encryption with local CFB mode
func encrypt(block cipher.Block, dst, src, buf []byte) {
	blocksize := block.BlockSize()
	tbl := buf[:blocksize]
	block.Encrypt(tbl, initialVector)
	n := len(src) / blocksize
	base := 0
	for i := 0; i < n; i++ {
		xorWords(dst[base:], src[base:], tbl)
		block.Encrypt(tbl, dst[base:])
		base += blocksize
	}
	xorBytes(dst[base:], src[base:], tbl)
}

func decrypt(block cipher.Block, dst, src, buf []byte) {
	blocksize := block.BlockSize()
	tbl := buf[:blocksize]
	next := buf[blocksize:]
	block.Encrypt(tbl, initialVector)
	n := len(src) / blocksize
	base := 0
	for i := 0; i < n; i++ {
		block.Encrypt(next, src[base:])
		xorWords(dst[base:], src[base:], tbl)
		tbl, next = next, tbl
		base += blocksize
	}
	xorBytes(dst[base:], src[base:], tbl)
}
