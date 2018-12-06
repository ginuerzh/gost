// SOCKS Protocol Version 4(a)
// https://www.openssh.com/txt/socks4.protocol
// https://www.openssh.com/txt/socks4a.protocol
package gosocks4

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	Ver4 = 4
)

const (
	CmdConnect uint8 = 1
	CmdBind          = 2
)

const (
	AddrIPv4   = 0
	AddrDomain = 1
)

const (
	Granted        = 90
	Failed         = 91
	Rejected       = 92
	RejectedUserid = 93
)

var (
	ErrBadVersion      = errors.New("Bad version")
	ErrBadFormat       = errors.New("Bad format")
	ErrBadAddrType     = errors.New("Bad address type")
	ErrShortDataLength = errors.New("Short data length")
	ErrBadCmd          = errors.New("Bad Command")
)

type Addr struct {
	Type int
	Host string
	Port uint16
}

func (addr *Addr) Decode(b []byte) error {
	if len(b) < 6 {
		return ErrShortDataLength
	}

	addr.Port = binary.BigEndian.Uint16(b[0:2])
	addr.Host = net.IP(b[2 : 2+net.IPv4len]).String()

	if b[2]|b[3]|b[4] == 0 && b[5] != 0 {
		addr.Type = AddrDomain
	}

	return nil
}

func (addr *Addr) Encode(b []byte) error {
	if len(b) < 6 {
		return ErrShortDataLength
	}

	binary.BigEndian.PutUint16(b[0:2], addr.Port)

	switch addr.Type {
	case AddrIPv4:
		ip4 := net.ParseIP(addr.Host).To4()
		if ip4 == nil {
			return ErrBadAddrType
		}
		copy(b[2:], ip4)
	case AddrDomain:
		ip4 := net.IPv4(0, 0, 0, 1)
		copy(b[2:], ip4.To4())
	default:
		return ErrBadAddrType
	}

	return nil
}

func (addr *Addr) String() string {
	return net.JoinHostPort(addr.Host, strconv.Itoa(int(addr.Port)))
}

/*
 +----+----+----+----+----+----+----+----+----+----+....+----+
 | VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
 +----+----+----+----+----+----+----+----+----+----+....+----+
    1    1      2              4           variable       1
*/
type Request struct {
	Cmd    uint8
	Addr   *Addr
	Userid []byte
}

func NewRequest(cmd uint8, addr *Addr, userid []byte) *Request {
	return &Request{
		Cmd:    cmd,
		Addr:   addr,
		Userid: userid,
	}
}

func ReadRequest(r io.Reader) (*Request, error) {
	br := bufio.NewReader(r)
	b, err := br.Peek(8)
	if err != nil {
		return nil, err
	}

	if b[0] != Ver4 {
		return nil, ErrBadVersion
	}

	request := &Request{
		Cmd: b[1],
	}

	addr := &Addr{}
	if err := addr.Decode(b[2:8]); err != nil {
		return nil, err
	}
	request.Addr = addr

	if _, err := br.Discard(8); err != nil {
		return nil, err
	}
	b, err = br.ReadBytes(0)
	if err != nil {
		return nil, err
	}
	request.Userid = b[:len(b)-1]

	if request.Addr.Type == AddrDomain {
		b, err = br.ReadBytes(0)
		if err != nil {
			return nil, err
		}
		request.Addr.Host = string(b[:len(b)-1])
	}

	return request, nil
}

func (r *Request) Write(w io.Writer) (err error) {
	bw := bufio.NewWriter(w)
	bw.Write([]byte{Ver4, r.Cmd})

	if r.Addr == nil {
		return ErrBadAddrType
	}

	var b [6]byte
	if err = r.Addr.Encode(b[:]); err != nil {
		return
	}
	bw.Write(b[:])

	if len(r.Userid) > 0 {
		bw.Write(r.Userid)
	}
	bw.WriteByte(0)

	if r.Addr.Type == AddrDomain {
		bw.WriteString(r.Addr.Host)
		bw.WriteByte(0)
	}

	return bw.Flush()
}

func (r *Request) String() string {
	addr := r.Addr
	if addr == nil {
		addr = &Addr{}
	}
	return fmt.Sprintf("%d %d %s", Ver4, r.Cmd, addr.String())
}

/*
 +----+----+----+----+----+----+----+----+
 | VN | CD | DSTPORT |      DSTIP        |
 +----+----+----+----+----+----+----+----+
 	1    1      2              4
*/
type Reply struct {
	Code uint8
	Addr *Addr
}

func NewReply(code uint8, addr *Addr) *Reply {
	return &Reply{
		Code: code,
		Addr: addr,
	}
}

func ReadReply(r io.Reader) (*Reply, error) {
	var b [8]byte

	_, err := io.ReadFull(r, b[:])
	if err != nil {
		return nil, err
	}

	if b[0] != 0 {
		return nil, ErrBadVersion
	}

	reply := &Reply{
		Code: b[1],
	}

	reply.Addr = &Addr{}
	if err := reply.Addr.Decode(b[2:]); err != nil {
		return nil, err
	}

	return reply, nil
}

func (r *Reply) Write(w io.Writer) (err error) {
	var b [8]byte

	b[1] = r.Code
	if r.Addr != nil {
		if err = r.Addr.Encode(b[2:]); err != nil {
			return
		}
	}

	_, err = w.Write(b[:])
	return
}

func (r *Reply) String() string {
	addr := r.Addr
	if addr == nil {
		addr = &Addr{}
	}
	return fmt.Sprintf("0 %d %s", r.Code, addr.String())
}
