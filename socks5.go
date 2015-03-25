package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	//"log"
	"bytes"
	"net"
)

const (
	Ver5 = 5
)

const (
	MethodNoAuth uint8 = iota
	MethodGSSAPI
	MethodUserPass
	// X'03' to X'7F' IANA ASSIGNED
	// X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	MethodNoAcceptable = 0xFF
)

const (
	CmdConnect uint8 = 1
	CmdBind          = 2
	CmdUdp           = 3
)

const (
	AddrIPv4   uint8 = 1
	AddrDomain       = 3
	AddrIPv6         = 4
)

const (
	Succeeded uint8 = iota
	Failure
	NotAllowed
	NetUnreachable
	HostUnreachable
	ConnRefused
	TTLExpired
	CmdUnsupported
	AddrUnsupported
)

var (
	ErrBadVersion  = errors.New("Bad version")
	ErrBadFormat   = errors.New("Bad format")
	ErrBadAddrType = errors.New("Bad address type")
	ErrShortBuffer = errors.New("Short buffer")

	cmdErrMap = map[uint8]error{
		Failure:         errors.New("General SOCKS server failure"),
		NotAllowed:      errors.New("Connection not allowed by ruleset"),
		NetUnreachable:  errors.New("Network unreachable"),
		HostUnreachable: errors.New("Host unreachable"),
		ConnRefused:     errors.New("Connection refused"),
		TTLExpired:      errors.New("TTL expired"),
		CmdUnsupported:  errors.New("Command not supported"),
		AddrUnsupported: errors.New("Address type not supported"),
	}
)

/*
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
*/
type Cmd struct {
	Cmd      uint8
	AddrType uint8
	Addr     string
	Port     uint16
}

func NewCmd(cmd uint8, atype uint8, addr string, port uint16) *Cmd {
	if len(addr) == 0 {
		addr = "0.0.0.0"
	}
	return &Cmd{
		Cmd:      cmd,
		AddrType: atype,
		Addr:     addr,
		Port:     port,
	}
}

func ReadCmd(r io.Reader) (*Cmd, error) {
	b := make([]byte, 256)
	n, err := r.Read(b)
	if err != nil {
		return nil, err
	}
	if n < 10 {
		return nil, ErrBadFormat
	}
	if b[0] != Ver5 {
		return nil, ErrBadVersion
	}

	cmd := &Cmd{
		Cmd:      b[1],
		AddrType: b[3],
	}

	pos := 4

	switch cmd.AddrType {
	case AddrIPv4:
		if n != 10 {
			return nil, ErrBadFormat
		}
		cmd.Addr = net.IP(b[pos : pos+net.IPv4len]).String()
		pos += net.IPv4len
	case AddrIPv6:
		if n != 22 {
			return nil, ErrBadFormat
		}
		cmd.Addr = net.IP(b[pos : pos+net.IPv6len]).String()
		pos += net.IPv6len
	case AddrDomain:
		length := int(b[pos])
		if n != 4+1+length+2 {
			return nil, ErrBadFormat
		}

		pos++
		cmd.Addr = string(b[pos : pos+length])
		pos += length
	default:
		pos += 4
	}

	cmd.Port = binary.BigEndian.Uint16(b[pos:])

	return cmd, nil
}

func (cmd *Cmd) Write(w io.Writer) (err error) {
	b := make([]byte, 256)

	b[0] = Ver5
	b[1] = cmd.Cmd
	b[3] = cmd.AddrType
	pos := 4

	switch cmd.AddrType {
	case AddrIPv4:
		pos += copy(b[pos:], net.ParseIP(cmd.Addr).To4())
	case AddrDomain:
		b[pos] = byte(len(cmd.Addr))
		pos++
		pos += copy(b[pos:], []byte(cmd.Addr))
	case AddrIPv6:
		pos += copy(b[pos:], net.ParseIP(cmd.Addr).To16())
	}
	binary.BigEndian.PutUint16(b[pos:], cmd.Port)
	pos += 2

	_, err = w.Write(b[:pos])

	return
}

func (cmd *Cmd) String() string {
	return fmt.Sprintf("5 %d 0 %d %s %d",
		cmd.Cmd, cmd.AddrType, cmd.Addr, cmd.Port)
}

/*
+----+------+------+----------+----------+----------+
|RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
+----+------+------+----------+----------+----------+
| 2  |  1   |  1   | Variable |    2     | Variable |
+----+------+------+----------+----------+----------+
*/
type UdpPayload struct {
	Rsv      uint16
	Frag     uint8
	AddrType uint8
	Addr     string
	Port     uint16
	Data     []byte
}

func NewUdpPayload(rsv uint16, atype uint8, addr string, port uint16, data []byte) *UdpPayload {
	if len(addr) == 0 {
		addr = "0.0.0.0"
	}
	return &UdpPayload{
		Rsv:      rsv,
		AddrType: atype,
		Addr:     addr,
		Port:     port,
		Data:     data,
	}
}

func ReadUdpPayload(r io.Reader) (*UdpPayload, error) {
	buf := make([]byte, 65797)
	n, err := io.ReadAtLeast(r, buf, 5)
	//log.Println("r", buf[:n])
	if err != nil {
		return nil, err
	}

	up := &UdpPayload{
		Rsv:      binary.BigEndian.Uint16(buf[:2]),
		Frag:     buf[2],
		AddrType: buf[3],
	}

	dataIndex := 0
	switch up.AddrType {
	case AddrIPv4:
		dataIndex = 10
	case AddrIPv6:
		dataIndex = 22
	case AddrDomain:
		dataIndex = 7 + int(buf[4])
	default:
		return nil, ErrBadAddrType
	}

	dataLen := int(up.Rsv)
	if n < dataIndex+dataLen {
		if _, err := io.ReadFull(r, buf[n:dataIndex+dataLen]); err != nil {
			return nil, err
		}
	}

	pos := 4
	switch up.AddrType {
	case AddrIPv4:
		up.Addr = net.IP(buf[pos : pos+net.IPv4len]).String()
		pos += net.IPv4len
	case AddrIPv6:
		up.Addr = net.IP(buf[pos : pos+net.IPv6len]).String()
		pos += net.IPv6len
	case AddrDomain:
		length := int(buf[pos])
		pos++
		up.Addr = string(buf[pos : pos+length])
		pos += length
	}

	up.Port = binary.BigEndian.Uint16(buf[pos:])
	//log.Println(up.Addr, up.Port)
	if dataLen > 0 {
		up.Data = buf[dataIndex : dataIndex+dataLen]
	} else {
		up.Data = buf[dataIndex:n]
	}

	return up, nil
}

func (up *UdpPayload) Write(w io.Writer) error {
	buffer := &bytes.Buffer{}

	b := make([]byte, 2)

	binary.BigEndian.PutUint16(b, up.Rsv)
	buffer.Write(b)
	buffer.WriteByte(up.Frag)
	buffer.WriteByte(up.AddrType)

	switch up.AddrType {
	case AddrIPv4:
		buffer.Write(net.ParseIP(up.Addr).To4())
	case AddrDomain:
		buffer.WriteByte(uint8(len(up.Addr)))
		buffer.Write([]byte(up.Addr))
	case AddrIPv6:
		buffer.Write(net.ParseIP(up.Addr).To16())
	}

	binary.BigEndian.PutUint16(b, up.Port)
	buffer.Write(b)
	buffer.Write(up.Data)

	_, err := w.Write(buffer.Bytes())

	return err
}

func (up *UdpPayload) String() string {
	return fmt.Sprintf("%d %d %d %s %d [%d]",
		up.Rsv, up.Frag, up.AddrType, up.Addr, up.Port, len(up.Data))
}
