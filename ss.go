package main

import (
	"encoding/binary"
	"fmt"
	"github.com/ginuerzh/gosocks5"
	"github.com/golang/glog"
	"github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"io"
	"net"
)

func handleShadow(conn net.Conn, arg Args) {
	if arg.User != nil {
		method := arg.User.Username()
		password, _ := arg.User.Password()
		cipher, err := shadowsocks.NewCipher(method, password)
		if err != nil {
			glog.V(LWARNING).Infoln("shadowsocks:", err)
			return
		}
		conn = shadowsocks.NewConn(conn, cipher)
	}

	addr, extra, err := getShadowRequest(conn)
	if err != nil {
		glog.V(LWARNING).Infoln("shadowsocks:", err)
		return
	}
	glog.V(LINFO).Infoln("shadowsocks connect:", addr.String())

	sconn, err := Connect(addr.String())
	if err != nil {
		glog.V(LWARNING).Infoln("shadowsocks:", err)
		return
	}
	defer sconn.Close()

	if extra != nil {
		if _, err := sconn.Write(extra); err != nil {
			glog.V(LWARNING).Infoln("shadowsocks:", err)
			return
		}
	}

	Transport(conn, sconn)
}

func getShadowRequest(conn net.Conn) (addr *gosocks5.Addr, extra []byte, err error) {
	const (
		idType  = 0 // address type index
		idIP0   = 1 // ip addres start index
		idDmLen = 1 // domain address length index
		idDm0   = 2 // domain address start index

		typeIPv4 = 1 // type is ipv4 address
		typeDm   = 3 // type is domain address
		typeIPv6 = 4 // type is ipv6 address

		lenIPv4   = 1 + net.IPv4len + 2 // 1addrType + ipv4 + 2port
		lenIPv6   = 1 + net.IPv6len + 2 // 1addrType + ipv6 + 2port
		lenDmBase = 1 + 1 + 2           // 1addrType + 1addrLen + 2port, plus addrLen
	)

	// buf size should at least have the same size with the largest possible
	// request size (when addrType is 3, domain name has at most 256 bytes)
	// 1(addrType) + 1(lenByte) + 256(max length address) + 2(port)
	buf := make([]byte, 1024)

	var n int
	// read till we get possible domain length field
	//shadowsocks.SetReadTimeout(conn)
	if n, err = io.ReadAtLeast(conn, buf, idDmLen+1); err != nil {
		return
	}

	addr = &gosocks5.Addr{
		Type: buf[idType],
	}

	reqLen := -1
	switch buf[idType] {
	case typeIPv4:
		reqLen = lenIPv4
	case typeIPv6:
		reqLen = lenIPv6
	case typeDm:
		reqLen = int(buf[idDmLen]) + lenDmBase
	default:
		err = fmt.Errorf("addr type %d not supported", buf[idType])
		return
	}

	if n < reqLen { // rare case
		//ss.SetReadTimeout(conn)
		if _, err = io.ReadFull(conn, buf[n:reqLen]); err != nil {
			return
		}
	} else if n > reqLen {
		// it's possible to read more than just the request head
		extra = buf[reqLen:n]
	}

	// Return string for typeIP is not most efficient, but browsers (Chrome,
	// Safari, Firefox) all seems using typeDm exclusively. So this is not a
	// big problem.
	switch buf[idType] {
	case typeIPv4:
		addr.Host = net.IP(buf[idIP0 : idIP0+net.IPv4len]).String()
	case typeIPv6:
		addr.Host = net.IP(buf[idIP0 : idIP0+net.IPv6len]).String()
	case typeDm:
		addr.Host = string(buf[idDm0 : idDm0+buf[idDmLen]])
	}
	// parse port
	addr.Port = binary.BigEndian.Uint16(buf[reqLen-2 : reqLen])

	return
}
