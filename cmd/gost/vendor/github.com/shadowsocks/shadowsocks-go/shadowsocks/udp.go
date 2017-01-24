package shadowsocks

import (
	"bytes"
	"fmt"
	"net"
	"time"
)

const (
	maxPacketSize = 4096 // increase it if error occurs
)

var (
	errPacketTooSmall  = fmt.Errorf("[udp]read error: cannot decrypt, received packet is smaller than ivLen")
	errPacketTooLarge  = fmt.Errorf("[udp]read error: received packet is latger than maxPacketSize(%d)", maxPacketSize)
	errBufferTooSmall  = fmt.Errorf("[udp]read error: given buffer is too small to hold data")
	errPacketOtaFailed = fmt.Errorf("[udp]read error: received packet has invalid ota")
)

type SecurePacketConn struct {
	net.PacketConn
	*Cipher
	ota bool
}

func NewSecurePacketConn(c net.PacketConn, cipher *Cipher, ota bool) *SecurePacketConn {
	return &SecurePacketConn{
		PacketConn: c,
		Cipher:     cipher,
		ota:        ota,
	}
}

func (c *SecurePacketConn) Close() error {
	return c.PacketConn.Close()
}

func (c *SecurePacketConn) ReadFrom(b []byte) (n int, src net.Addr, err error) {
	ota := false
	cipher := c.Copy()
	buf := make([]byte, 4096)
	n, src, err = c.PacketConn.ReadFrom(buf)
	if err != nil {
		return
	}

	if n < c.info.ivLen {
		return 0, nil, errPacketTooSmall
	}

	if len(b) < n-c.info.ivLen {
		err = errBufferTooSmall // just a warning
	}

	iv := make([]byte, c.info.ivLen)
	copy(iv, buf[:c.info.ivLen])

	if err = cipher.initDecrypt(iv); err != nil {
		return
	}

	cipher.decrypt(b[0:], buf[c.info.ivLen:n])
	n -= c.info.ivLen
	if b[idType]&OneTimeAuthMask > 0 {
		ota = true
	}

	if c.ota && !ota {
		return 0, src, errPacketOtaFailed
	}

	if ota {
		key := cipher.key
		actualHmacSha1Buf := HmacSha1(append(iv, key...), b[:n-lenHmacSha1])
		if !bytes.Equal(b[n-lenHmacSha1:n], actualHmacSha1Buf) {
			Debug.Printf("verify one time auth failed, iv=%v key=%v data=%v", iv, key, b)
			return 0, src, errPacketOtaFailed
		}
		n -= lenHmacSha1
	}

	return
}

func (c *SecurePacketConn) WriteTo(b []byte, dst net.Addr) (n int, err error) {
	cipher := c.Copy()
	iv, err := cipher.initEncrypt()
	if err != nil {
		return
	}
	packetLen := len(b) + len(iv)

	if c.ota {
		b[idType] |= OneTimeAuthMask
		packetLen += lenHmacSha1
		key := cipher.key
		actualHmacSha1Buf := HmacSha1(append(iv, key...), b)
		b = append(b, actualHmacSha1Buf...)
	}

	cipherData := make([]byte, packetLen)
	copy(cipherData, iv)

	cipher.encrypt(cipherData[len(iv):], b)
	n, err = c.PacketConn.WriteTo(cipherData, dst)
	if c.ota {
		n -= lenHmacSha1
	}
	return
}

func (c *SecurePacketConn) LocalAddr() net.Addr {
	return c.PacketConn.LocalAddr()
}

func (c *SecurePacketConn) SetDeadline(t time.Time) error {
	return c.PacketConn.SetDeadline(t)
}

func (c *SecurePacketConn) SetReadDeadline(t time.Time) error {
	return c.PacketConn.SetReadDeadline(t)
}

func (c *SecurePacketConn) SetWriteDeadline(t time.Time) error {
	return c.PacketConn.SetWriteDeadline(t)
}

func (c *SecurePacketConn) IsOta() bool {
	return c.ota
}

func (c *SecurePacketConn) ForceOTA() net.PacketConn {
	return NewSecurePacketConn(c.PacketConn, c.Cipher.Copy(), true)
}
