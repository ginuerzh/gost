package dissector

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	handshakeHeaderLen = 4
)

const (
	HelloRequest = 0
	ClientHello  = 1
	ServerHello  = 2
)

type Random struct {
	Time   uint32
	Opaque [28]byte
}

type CipherSuite uint16

type CompressionMethod uint8

type ClientHelloHandshake struct {
	Version            Version
	Random             Random
	SessionID          []byte
	CipherSuites       []CipherSuite
	CompressionMethods []CompressionMethod
	Extensions         []Extension
}

func (h *ClientHelloHandshake) Encode() (data []byte, err error) {
	buf := new(bytes.Buffer)
	if _, err = h.WriteTo(buf); err != nil {
		return
	}
	data = buf.Bytes()
	return
}

func (h *ClientHelloHandshake) Decode(data []byte) (err error) {
	_, err = h.ReadFrom(bytes.NewReader(data))
	return
}

func (h *ClientHelloHandshake) ReadFrom(r io.Reader) (n int64, err error) {
	b := make([]byte, handshakeHeaderLen)
	nn, err := io.ReadFull(r, b)
	n += int64(nn)
	if err != nil {
		return
	}

	if b[0] != ClientHello {
		err = ErrBadType
		return
	}

	length := int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if length < 34 { // length of version + random
		err = fmt.Errorf("bad length, need at least 34 bytes, got %d", length)
		return
	}

	b = make([]byte, length)
	nn, err = io.ReadFull(r, b)
	n += int64(nn)
	if err != nil {
		return
	}
	h.Version = Version(binary.BigEndian.Uint16(b[:2]))
	if h.Version < tls.VersionTLS12 {
		err = fmt.Errorf("bad version: only TLSv1.2 is supported")
		return
	}

	pos := 2
	h.Random.Time = binary.BigEndian.Uint32(b[pos : pos+4])
	pos += 4
	copy(h.Random.Opaque[:], b[pos:pos+28])
	pos += 28

	nn, err = h.readSession(b[pos:])
	if err != nil {
		return
	}
	pos += nn

	nn, err = h.readCipherSuites(b[pos:])
	if err != nil {
		return
	}
	pos += nn

	nn, err = h.readCompressionMethods(b[pos:])
	if err != nil {
		return
	}
	pos += nn

	nn, err = h.readExtensions(b[pos:])
	if err != nil {
		return
	}
	// pos += nn

	return
}

func (h *ClientHelloHandshake) readSession(b []byte) (n int, err error) {
	if len(b) == 0 {
		err = fmt.Errorf("bad length: data too short for session")
		return
	}

	nlen := int(b[0])
	n++
	if len(b) < n+nlen {
		err = fmt.Errorf("bad length: malformed data for session")
	}
	if nlen > 0 && n+nlen <= len(b) {
		h.SessionID = make([]byte, nlen)
		copy(h.SessionID, b[n:n+nlen])
		n += nlen
	}

	return
}

func (h *ClientHelloHandshake) readCipherSuites(b []byte) (n int, err error) {
	if len(b) < 2 {
		err = fmt.Errorf("bad length: data too short for cipher suites")
		return
	}

	nlen := int(binary.BigEndian.Uint16(b[:2]))
	n += 2
	if len(b) < n+nlen {
		err = fmt.Errorf("bad length: malformed data for cipher suites")
	}
	for i := 0; i < nlen/2; i++ {
		h.CipherSuites = append(h.CipherSuites, CipherSuite(binary.BigEndian.Uint16(b[n:n+2])))
		n += 2
	}

	return
}

func (h *ClientHelloHandshake) readCompressionMethods(b []byte) (n int, err error) {
	if len(b) == 0 {
		err = fmt.Errorf("bad length: data too short for compression methods")
		return
	}
	nlen := int(b[0])
	n++
	if len(b) < n+nlen {
		err = fmt.Errorf("bad length: malformed data for compression methods")
	}
	for i := 0; i < nlen; i++ {
		h.CompressionMethods = append(h.CompressionMethods, CompressionMethod(b[n]))
		n++
	}
	return
}

func (h *ClientHelloHandshake) readExtensions(b []byte) (n int, err error) {
	if len(b) < 2 {
		err = fmt.Errorf("bad length: data too short for extensions")
		return
	}
	nlen := int(binary.BigEndian.Uint16(b[:2]))
	n += 2
	if len(b) < n+nlen {
		err = fmt.Errorf("bad length: malformed data for extensions")
		return
	}

	br := bytes.NewReader(b[n:])
	for br.Len() > 0 {
		cn := br.Len()
		var ext Extension
		ext, err = ReadExtension(br)
		if err != nil {
			return
		}
		h.Extensions = append(h.Extensions, ext)
		n += (cn - br.Len())
	}

	return
}

func (h *ClientHelloHandshake) WriteTo(w io.Writer) (n int64, err error) {
	buf := &bytes.Buffer{}
	buf.WriteByte(ClientHello)
	buf.Write([]byte{0, 0, 0}) // placeholder for payload length
	binary.Write(buf, binary.BigEndian, h.Version)
	pos := 6
	binary.Write(buf, binary.BigEndian, h.Random.Time)
	buf.Write(h.Random.Opaque[:])
	pos += 32
	buf.WriteByte(byte(len(h.SessionID)))
	buf.Write(h.SessionID)
	pos += (1 + len(h.SessionID))
	binary.Write(buf, binary.BigEndian, uint16(len(h.CipherSuites)*2))
	for _, cs := range h.CipherSuites {
		binary.Write(buf, binary.BigEndian, cs)
	}
	pos += (2 + len(h.CipherSuites)*2)
	buf.WriteByte(byte(len(h.CompressionMethods)))
	for _, cm := range h.CompressionMethods {
		buf.WriteByte(byte(cm))
	}
	pos += (1 + len(h.CompressionMethods))
	buf.Write([]byte{0, 0}) // placeholder for extensions length

	extLen := 0
	for _, ext := range h.Extensions {
		nn, _ := buf.Write(ext.Bytes())
		extLen += nn
	}

	b := buf.Bytes()
	plen := len(b) - handshakeHeaderLen
	b[1], b[2], b[3] = byte((plen>>16)&0xFF), byte((plen>>8)&0xFF), byte(plen&0xFF) // payload length
	b[pos], b[pos+1] = byte((extLen>>8)&0xFF), byte(extLen&0xFF)                    // extensions length

	nn, err := w.Write(b)
	n = int64(nn)
	return
}
