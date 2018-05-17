package stun

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sort"
	"strconv"
)

const (
	KindRequest    uint16 = 0x0000
	KindIndication uint16 = 0x0010
	KindResponse   uint16 = 0x0100
	KindError      uint16 = 0x0110
)

// Message represents a STUN message.
type Message struct {
	Type        uint16
	Transaction []byte
	Attributes  []Attr
}

func (m *Message) Marshal(p []byte) []byte {
	pos := len(p)
	r, b := grow(p, 20)
	be.PutUint16(b, m.Type)

	if m.Transaction != nil {
		copy(b[4:], m.Transaction)
	} else {
		copy(b[4:], magicCookie)
		rand.Read(b[8:20])
	}

	sort.Sort(byPosition(m.Attributes))
	for _, attr := range m.Attributes {
		r = m.marshalAttr(r, attr, pos)
	}

	be.PutUint16(r[pos+2:], uint16(len(r)-pos-20))
	return r
}

func (m *Message) marshalAttr(p []byte, attr Attr, pos int) []byte {
	h := len(p)
	r, b := grow(p, 4)
	be.PutUint16(b, attr.Type())

	switch v := attr.(type) {
	case *addr:
		r = v.MarshalAddr(r, r[pos+4:])
	case *integrity:
		r = v.MarshalSum(r, r[pos:])
	case *fingerprint:
		r = v.MarshalSum(r, r[pos:])
	default:
		r = v.Marshal(r)
	}
	n := len(r) - h - 4
	be.PutUint16(r[h+2:], uint16(n))

	if pad := n & 3; pad != 0 {
		r, b = grow(r, 4-pad)
		for i := range b {
			b[i] = 0
		}
	}
	return r
}

func (m *Message) Unmarshal(b []byte) (n int, err error) {
	if len(b) < 20 {
		err = io.EOF
		return
	}
	l := int(be.Uint16(b[2:])) + 20
	if len(b) < l {
		err = io.EOF
		return
	}
	pos, p := 20, make([]byte, l)
	copy(p, b[:l])

	m.Type = be.Uint16(p)
	m.Transaction = p[4:20]

	for pos < len(p) {
		s, attr, err := m.unmarshalAttr(p, pos)
		if err != nil {
			return 0, err
		}
		pos += s
		if attr != nil {
			m.Attributes = append(m.Attributes, attr)
		}
	}

	return l, nil
}

func (m *Message) unmarshalAttr(p []byte, pos int) (n int, attr Attr, err error) {
	b := p[pos:]
	if len(b) < 4 {
		err = errFormat
		return
	}
	typ := be.Uint16(b)
	attr, n = newAttr(typ), int(be.Uint16(b[2:]))+4
	if len(b) < n {
		err = errFormat
		return
	}

	b = b[4:n]
	if attr != nil {
		switch v := attr.(type) {
		case *addr:
			err = v.UnmarshalAddr(b, m.Transaction)
		case *integrity:
			err = v.UnmarshalSum(b, p[:pos+n])
		case *fingerprint:
			err = v.UnmarshalSum(b, p[:pos+n])
		default:
			err = attr.Unmarshal(b)
		}
	} else if typ < 0x8000 {
		err = errFormat
	}
	if err != nil {
		err = &errAttribute{err, typ}
		return
	}
	if pad := n & 3; pad != 0 {
		n += 4 - pad
		if len(p) < pos+n {
			err = errFormat
		}
	}
	return
}

func (m *Message) Kind() uint16 {
	return m.Type & 0x110
}

func (m *Message) Method() uint16 {
	return m.Type &^ 0x110
}

func (m *Message) Add(attr Attr) {
	m.Attributes = append(m.Attributes, attr)
}

func (m *Message) Set(attr Attr) {
	m.Del(attr.Type())
	m.Add(attr)
}

func (m *Message) Del(typ uint16) {
	n := 0
	for _, a := range m.Attributes {
		if a.Type() != typ {
			m.Attributes[n] = a
			n++
		}
	}
	m.Attributes = m.Attributes[:n]
}

func (m *Message) Get(typ uint16) (attr Attr) {
	for _, attr = range m.Attributes {
		if attr.Type() == typ {
			return
		}
	}
	return nil
}

func (m *Message) Has(typ uint16) bool {
	for _, attr := range m.Attributes {
		if attr.Type() == typ {
			return true
		}
	}
	return false
}

func (m *Message) GetString(typ uint16) string {
	if str, ok := m.Get(typ).(fmt.Stringer); ok {
		return str.String()
	}
	return ""
}

func (m *Message) GetAddr(network string, typ ...uint16) net.Addr {
	for _, t := range typ {
		if addr, ok := m.Get(t).(*addr); ok {
			return addr.Addr(network)
		}
	}
	return nil
}

func (m *Message) GetInt(typ uint16) (v uint64, ok bool) {
	attr := m.Get(typ)
	if r, ok := attr.(*number); ok {
		return r.v, true
	}
	return
}

func (m *Message) GetBytes(typ uint16) []byte {
	if attr, ok := m.Get(typ).(*raw); ok {
		return attr.data
	}
	return nil
}

func (m *Message) GetError() *Error {
	if err, ok := m.Get(AttrErrorCode).(*Error); ok {
		return err
	}
	return nil
}

func (m *Message) CheckIntegrity(key []byte) bool {
	if attr, ok := m.Get(AttrMessageIntegrity).(*integrity); ok {
		return attr.Check(key)
	}
	return false
}

func (m *Message) CheckFingerprint() bool {
	if attr, ok := m.Get(AttrFingerprint).(*fingerprint); ok {
		return attr.Check()
	}
	return false
}

func (m *Message) String() string {
	sort.Sort(byPosition(m.Attributes))

	// TODO: use sprintf

	b := &bytes.Buffer{}
	b.WriteString(MethodName(m.Type))
	b.WriteByte('{')
	tx := m.Transaction
	if tx == nil {
		b.WriteString("nil")
	} else if bytes.Equal(magicCookie, tx[:4]) {
		b.WriteString(hex.EncodeToString(tx[4:]))
	} else {
		b.WriteString(hex.EncodeToString(tx))
	}
	for _, attr := range m.Attributes {
		b.WriteString(", ")
		b.WriteString(AttrName(attr.Type()))
		switch v := attr.(type) {
		case *raw:
			b.WriteString(": \"")
			b.Write(v.data)
			b.WriteByte('"')
		case *str:
			b.WriteString(": \"")
			b.WriteString(v.data)
			b.WriteByte('"')
		case flag, *integrity, *fingerprint:
		default:
			b.WriteString(fmt.Sprintf(": %v", attr))
		}
	}
	b.WriteByte('}')
	return b.String()
}

func MethodName(typ uint16) string {
	if r, ok := methodNames[typ&^0x110]; ok {
		switch typ & 0x110 {
		case KindRequest:
			return r + "Request"
		case KindIndication:
			return r + "Indication"
		case KindResponse:
			return r + "Response"
		case KindError:
			return r + "Error"
		}
	}
	return "0x" + strconv.FormatUint(uint64(typ), 16)
}

func UnmarshalMessage(b []byte) (*Message, error) {
	m := &Message{}
	if _, err := m.Unmarshal(b); err != nil {
		return nil, err
	}
	return m, nil
}

var magicCookie = []byte{0x21, 0x12, 0xa4, 0x42}
var alphanum = dict("01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

type dict []byte

func (d dict) rand(n int) string {
	m, b := len(d), make([]byte, n)
	for i := range b {
		b[i] = d[rand.Intn(m)]
	}
	return string(b)
}

func NewTransaction() []byte {
	id := make([]byte, 16)
	copy(id, magicCookie)
	rand.Read(id[4:]) // TODO: configure random source
	return id
}

type byPosition []Attr

func (s byPosition) Len() int      { return len(s) }
func (s byPosition) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s byPosition) Less(i, j int) bool {
	a, b := s[i].Type(), s[j].Type()
	switch b {
	case a:
		return i < j
	case AttrMessageIntegrity:
		return a != AttrFingerprint
	case AttrFingerprint:
		return true
	default:
		return i < j
	}
}

type errAttribute struct {
	error
	typ uint16
}

func (err errAttribute) Error() string {
	return "attribute " + AttrName(err.typ) + ": " + err.error.Error()
}
