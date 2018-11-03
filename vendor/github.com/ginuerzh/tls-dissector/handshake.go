package dissector

import (
	"bytes"
	"encoding/binary"
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
	b = make([]byte, length)
	nn, err = io.ReadFull(r, b)
	n += int64(nn)
	if err != nil {
		return
	}
	h.Version = Version(binary.BigEndian.Uint16(b[:2]))

	pos := 2
	h.Random.Time = binary.BigEndian.Uint32(b[pos : pos+4])
	pos += 4
	copy(h.Random.Opaque[:], b[pos:pos+28])
	pos += 28

	sessionLen := int(b[pos])
	pos++
	h.SessionID = make([]byte, sessionLen)
	copy(h.SessionID, b[pos:pos+sessionLen])
	pos += sessionLen

	cipherLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	for i := 0; i < cipherLen/2; i++ {
		h.CipherSuites = append(h.CipherSuites, CipherSuite(binary.BigEndian.Uint16(b[pos:pos+2])))
		pos += 2
	}

	compLen := int(b[pos])
	pos++
	for i := 0; i < compLen; i++ {
		h.CompressionMethods = append(h.CompressionMethods, CompressionMethod(b[pos]))
		pos++
	}

	// extLen := int(binary.BigEndian.Uint16(b[pos : pos+2]))
	pos += 2
	if pos >= len(b) {
		return
	}

	br := bytes.NewReader(b[pos:])
	for br.Len() > 0 {
		var ext Extension
		ext, err = ReadExtension(br)
		if err != nil {
			return
		}
		h.Extensions = append(h.Extensions, ext)
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
