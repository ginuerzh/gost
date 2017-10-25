package dissector

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

const (
	RecordHeaderLen = 5
)

const (
	Handshake = 0x16
)

var (
	ErrBadType = errors.New("bad type")
)

type Version uint16

type Record struct {
	Type    uint8
	Version Version
	Opaque  []byte
}

func ReadRecord(r io.Reader) (*Record, error) {
	record := &Record{}
	if _, err := record.ReadFrom(r); err != nil {
		return nil, err
	}
	return record, nil
}

func (rec *Record) ReadFrom(r io.Reader) (n int64, err error) {
	b := make([]byte, RecordHeaderLen)
	nn, err := io.ReadFull(r, b)
	n += int64(nn)
	if err != nil {
		return
	}
	rec.Type = b[0]
	rec.Version = Version(binary.BigEndian.Uint16(b[1:3]))
	length := int(binary.BigEndian.Uint16(b[3:5]))
	rec.Opaque = make([]byte, length)
	nn, err = io.ReadFull(r, rec.Opaque)
	n += int64(nn)
	return
}

func (rec *Record) WriteTo(w io.Writer) (n int64, err error) {
	buf := &bytes.Buffer{}
	buf.WriteByte(rec.Type)
	binary.Write(buf, binary.BigEndian, rec.Version)
	binary.Write(buf, binary.BigEndian, uint16(len(rec.Opaque)))
	buf.Write(rec.Opaque)
	return buf.WriteTo(w)
}
