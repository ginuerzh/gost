package stun

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
)

// Attribute represents a STUN attribute.
type Attr interface {
	Type() uint16
	Marshal(p []byte) []byte
	Unmarshal(b []byte) error
}

// IP address family
const (
	IPv4 = 0x01
	IPv6 = 0x02
)

// IP address family
const (
	ChangeIP   uint64 = 0x04
	ChangePort        = 0x02
)

func newAttr(typ uint16) Attr {
	switch typ {
	case AttrMappedAddress, AttrXorPeerAddress, AttrXorRelayedAddress,
		AttrXorMappedAddress, AttrAlternateServer, AttrResponseOrigin, AttrOtherAddress,
		AttrResponseAddress, AttrSourceAddress, AttrChangedAddress, AttrReflectedFrom:
		return &addr{typ: typ}
	case AttrRequestedAddressFamily, AttrRequestedTransport:
		return &number{typ: typ, size: 4, pad: 24}
	case AttrChannelNumber, AttrResponsePort:
		return &number{typ: typ, size: 4, pad: 16}
	case AttrLifetime, AttrConnectionID, AttrCacheTimeout,
		AttrBandwidth, AttrTimerVal,
		AttrTransactionTransmitCounter,
		AttrEcnCheck, AttrChangeRequest, AttrPriority:
		return &number{typ: typ, size: 4}
	case AttrIceControlled, AttrIceControlling:
		return &number{typ: typ, size: 8}
	case AttrUsername, AttrRealm, AttrNonce, AttrSoftware, AttrPassword, AttrThirdPartyAuthorization,
		AttrData, AttrAccessToken, AttrReservationToken, AttrMobilityTicket, AttrPadding, AttrUnknownAttributes:
		return &raw{typ: typ}
	case AttrMessageIntegrity:
		return &integrity{}
	case AttrErrorCode:
		return &Error{}
	case AttrEvenPort:
		return &number{typ: typ, size: 1}
	case AttrDontFragment, AttrUseCandidate:
		return flag(typ)
	case AttrFingerprint:
		return &fingerprint{}
	}
	return nil
}

func AttrName(typ uint16) string {
	if r, ok := attrNames[typ]; ok {
		return r
	}
	return "0x" + strconv.FormatUint(uint64(typ), 16)
}

func Int(typ uint16, v uint64) Attr {
	switch typ {
	case AttrRequestedAddressFamily, AttrRequestedTransport:
		return &number{typ, 4, 24, v}
	case AttrChannelNumber, AttrResponsePort:
		return &number{typ, 4, 16, v}
	case AttrIceControlled, AttrIceControlling:
		return &number{typ, 8, 0, v}
	case AttrEvenPort:
		return &number{typ, 1, 0, v}
	default:
		return &number{typ, 4, 0, v}
	}
}

type number struct {
	typ       uint16
	size, pad uint8
	v         uint64
}

func (a *number) Type() uint16 { return a.typ }

func (a *number) Marshal(p []byte) []byte {
	r, b := grow(p, int(a.size))
	switch a.size {
	case 1:
		b[0] = byte(a.v)
	case 4:
		be.PutUint32(b, uint32(a.v<<a.pad))
	case 8:
		be.PutUint64(b, a.v<<a.pad)
	}
	return r
}

func (a *number) Unmarshal(b []byte) error {
	if len(b) < int(a.size) {
		return errFormat
	}
	switch a.size {
	case 1:
		a.v = uint64(b[0])
	case 4:
		a.v = uint64(be.Uint32(b) >> a.pad)
	case 8:
		a.v = be.Uint64(b) >> a.pad
	}
	return nil
}

func (a *number) String() string {
	return "0x" + strconv.FormatUint(a.v, 16)
}

func Flag(v uint16) Attr {
	return flag(v)
}

type flag uint16

func (attr flag) Type() uint16        { return uint16(attr) }
func (flag) Marshal(p []byte) []byte  { return p }
func (flag) Unmarshal(b []byte) error { return nil }

// Error represents the ERROR-CODE attribute.
type Error struct {
	Code   int
	Reason string
}

func NewError(code int) *Error {
	return &Error{code, ErrorText(code)}
}

func (*Error) Type() uint16 { return AttrErrorCode }

func (e *Error) Marshal(p []byte) []byte {
	r, b := grow(p, 4+len(e.Reason))
	b[0] = 0
	b[1] = 0
	b[2] = byte(e.Code / 100)
	b[3] = byte(e.Code % 100)
	copy(b[4:], e.Reason)
	return r
}

func (e *Error) Unmarshal(b []byte) error {
	if len(b) < 4 {
		return errFormat
	}
	e.Code = int(b[2])*100 + int(b[3])
	e.Reason = getString(b[4:])
	return nil
}

func (e *Error) Error() string  { return e.String() }
func (e *Error) String() string { return fmt.Sprintf("%d %s", e.Code, e.Reason) }

// ErrorText returns a text for the STUN error code. It returns the empty string if the code is unknown.
func ErrorText(code int) string { return errorText[code] }

func getString(b []byte) string {
	for i := len(b); i >= 0; i-- {
		if b[i-1] > 0 {
			return string(b[:i])
		}
	}
	return ""
}

func Addr(typ uint16, v net.Addr) Attr {
	ip, port := SockAddr(v)
	return &addr{typ, ip, port}
}

func SockAddr(v net.Addr) (net.IP, int) {
	switch a := v.(type) {
	case *net.UDPAddr:
		return a.IP, a.Port
	case *net.TCPAddr:
		return a.IP, a.Port
	case *net.IPAddr:
		return a.IP, 0
	default:
		return net.IPv4zero, 0
	}
}

func sameAddr(a, b net.Addr) bool {
	aip, aport := SockAddr(a)
	bip, bport := SockAddr(b)
	return aip.Equal(bip) && aport == bport
}

func NewAddr(network string, ip net.IP, port int) net.Addr {
	switch network {
	case "udp", "udp4", "udp6":
		return &net.UDPAddr{IP: ip, Port: port}
	case "tcp", "tcp4", "tcp6":
		return &net.TCPAddr{IP: ip, Port: port}
	}
	return &net.IPAddr{IP: ip}
}

func IP(typ uint16, ip net.IP) Attr { return &addr{typ, ip, 0} }

type addr struct {
	typ  uint16
	IP   net.IP
	Port int
}

func (addr *addr) Type() uint16 { return addr.typ }

func (addr *addr) Addr(network string) net.Addr {
	return NewAddr(network, addr.IP, addr.Port)
}

func (addr *addr) Xored() bool {
	switch addr.typ {
	case AttrXorMappedAddress, AttrXorPeerAddress, AttrXorRelayedAddress:
		return true
	default:
		return false
	}
}

func (addr *addr) Marshal(p []byte) []byte {
	return addr.MarshalAddr(p, nil)
}

func (addr *addr) MarshalAddr(p, tx []byte) []byte {
	fam, ip := IPv4, addr.IP.To4()
	if ip == nil {
		fam, ip = IPv6, addr.IP
	}
	r, b := grow(p, 4+len(ip))
	b[0] = 0
	b[1] = byte(fam)
	if addr.Xored() && tx != nil {
		be.PutUint16(b[2:], uint16(addr.Port)^0x2112)
		b = b[4:]
		for i, it := range ip {
			b[i] = it ^ tx[i]
		}
	} else {
		be.PutUint16(b[2:], uint16(addr.Port))
		copy(b[4:], ip)
	}
	return r
}

func (addr *addr) Unmarshal(b []byte) error {
	return addr.UnmarshalAddr(b, nil)
}

func (addr *addr) UnmarshalAddr(b, tx []byte) error {
	if len(b) < 4 {
		return errFormat
	}
	n, port := net.IPv4len, int(be.Uint16(b[2:]))
	if b[1] == IPv6 {
		n = net.IPv6len
	}
	if b = b[4:]; len(b) < n {
		return errFormat
	}
	addr.IP = make(net.IP, n)
	if addr.Xored() && tx != nil {
		for i, it := range b {
			addr.IP[i] = it ^ tx[i]
		}
		addr.Port = port ^ 0x2112
	} else {
		copy(addr.IP, b)
		addr.Port = port
	}
	return nil
}

func (addr *addr) Equal(a *addr) bool {
	return addr == a || (addr != nil && a != nil && addr.IP.Equal(a.IP) && addr.Port == a.Port)
}

func (addr *addr) String() string {
	if addr.Port == 0 {
		return addr.IP.String()
	}
	return net.JoinHostPort(addr.IP.String(), strconv.Itoa(addr.Port))
}

func Bytes(typ uint16, v []byte) Attr { return &raw{typ, v} }

type raw struct {
	typ  uint16
	data []byte
}

func (attr *raw) Type() uint16            { return attr.typ }
func (attr *raw) Marshal(p []byte) []byte { return append(p, attr.data...) }
func (attr *raw) Unmarshal(p []byte) error {
	attr.data = p
	return nil
}
func (attr *raw) String() string { return string(attr.data) }

func String(typ uint16, v string) Attr {
	return &str{typ, v}
}

type str struct {
	typ  uint16
	data string
}

func (attr *str) Type() uint16            { return attr.typ }
func (attr *str) Marshal(p []byte) []byte { return append(p, attr.data...) }
func (attr *str) Unmarshal(p []byte) error {
	attr.data = string(p)
	return nil
}
func (attr *str) String() string { return attr.data }

func MessageIntegrity(key []byte) Attr {
	return &integrity{key: key}
}

type integrity struct {
	key, sum, raw []byte
}

func (*integrity) Type() uint16 {
	return AttrMessageIntegrity
}

func (attr *integrity) Marshal(p []byte) []byte {
	return append(p, attr.sum...)
}

func (attr *integrity) Unmarshal(b []byte) error {
	if len(b) < 20 {
		return errFormat
	}
	attr.sum = b
	return nil
}

func (attr *integrity) MarshalSum(p, raw []byte) []byte {
	n := len(raw) - 4
	be.PutUint16(raw[2:], uint16(n+4))
	return attr.Sum(attr.key, raw[:n], p)
}

func (attr *integrity) UnmarshalSum(p, raw []byte) error {
	attr.raw = raw
	return attr.Unmarshal(p)
}

func (attr *integrity) Sum(key, data, p []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(p)
}

func (attr *integrity) Check(key []byte) bool {
	r := attr.raw
	if len(r) < 44 {
		return r == nil
	}
	be.PutUint16(r[2:], uint16(len(r)-20))
	h := attr.Sum(key, r[:len(r)-24], nil)
	return bytes.Equal(h, attr.sum)
}

var Fingerprint Attr = &fingerprint{}

type fingerprint struct {
	sum uint32
	raw []byte
}

func (*fingerprint) Type() uint16 {
	return AttrFingerprint
}

func (attr *fingerprint) Marshal(p []byte) []byte {
	r, b := grow(p, 4)
	be.PutUint32(b, attr.sum)
	return r
}

func (attr *fingerprint) Unmarshal(b []byte) error {
	if len(b) < 4 {
		return errFormat
	}
	attr.sum = be.Uint32(b)
	return nil
}

func (attr *fingerprint) MarshalSum(p, raw []byte) []byte {
	n := len(raw) - 4
	be.PutUint16(raw[2:], uint16(n-12))
	v := attr.Sum(raw[:n])
	r, b := grow(p, 4)
	be.PutUint32(b, v)
	return r
}

func (attr *fingerprint) UnmarshalSum(p, raw []byte) error {
	attr.raw = raw
	return attr.Unmarshal(p)
}

func (attr *fingerprint) Sum(p []byte) uint32 {
	return crc32.ChecksumIEEE(p) ^ 0x5354554e
}

func (attr *fingerprint) Check() bool {
	r := attr.raw
	if len(r) < 28 {
		return r == nil
	}
	be.PutUint16(r[2:], uint16(len(r)-20))
	return attr.Sum(r[:len(r)-8]) == attr.sum
}
