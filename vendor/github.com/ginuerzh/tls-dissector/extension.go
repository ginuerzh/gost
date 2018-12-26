package dissector

import (
	"bytes"
	"encoding/binary"
	"io"
)

const (
	ExtServerName uint16 = 0x0000
)

type Extension interface {
	Type() uint16
	Bytes() []byte
}

func ReadExtension(r io.Reader) (ext Extension, err error) {
	b := make([]byte, 4)
	if _, err = io.ReadFull(r, b); err != nil {
		return
	}
	bb := make([]byte, int(binary.BigEndian.Uint16(b[2:4])))
	if _, err = io.ReadFull(r, bb); err != nil {
		return nil, err
	}

	t := binary.BigEndian.Uint16(b[:2])
	switch t {
	case ExtServerName:
		ext = &ServerNameExtension{
			NameType: bb[2],
			Name:     string(bb[5:]),
		}

	default:
		ext = &unknownExtension{
			raw: append(b, bb...),
		}
	}

	return
}

type unknownExtension struct {
	raw []byte
}

func NewExtension(t uint16, data []byte) Extension {
	ext := &unknownExtension{
		raw: make([]byte, 2+2+len(data)),
	}
	binary.BigEndian.PutUint16(ext.raw[:2], t)
	binary.BigEndian.PutUint16(ext.raw[2:4], uint16(len(data)))
	copy(ext.raw[4:], data)
	return ext
}

func (ext *unknownExtension) Type() uint16 {
	return binary.BigEndian.Uint16(ext.raw)
}

func (ext *unknownExtension) Bytes() []byte {
	return ext.raw
}

type ServerNameExtension struct {
	NameType uint8
	Name     string
}

func (ext *ServerNameExtension) Type() uint16 {
	return ExtServerName
}

func (ext *ServerNameExtension) Bytes() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, ExtServerName)
	binary.Write(buf, binary.BigEndian, uint16(2+1+2+len(ext.Name)))
	binary.Write(buf, binary.BigEndian, uint16(1+2+len(ext.Name)))
	buf.WriteByte(ext.NameType)
	binary.Write(buf, binary.BigEndian, uint16(len(ext.Name)))
	buf.WriteString(ext.Name)
	return buf.Bytes()
}
