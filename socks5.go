package main

import (
	"github.com/ginuerzh/gosocks5"
	"github.com/shadowsocks/shadowsocks-go/shadowsocks"
	"net"
	//"strconv"
	"crypto/tls"
	"log"
)

const (
	rawCert = `-----BEGIN CERTIFICATE-----
MIIC5jCCAdCgAwIBAgIBADALBgkqhkiG9w0BAQUwEjEQMA4GA1UEChMHQWNtZSBD
bzAeFw0xNDAzMTcwNjIwNTFaFw0xNTAzMTcwNjIwNTFaMBIxEDAOBgNVBAoTB0Fj
bWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDccNO1xmd4lWSf
d/0/QS3E93cYIWHw831i/IKxigdRD/XMZonLdEHywW6lOiXazaP8e6CqPGSmnl0x
5k/3dvGCMj2JCVxM6+z7NpL+AiwvXmvkj/TOciCgwqssCwYS2CiVwjfazRjx1ZUJ
VDC5qiyRsfktQ2fVHrpnJGVSRagmiQgwGWBilVG9B8QvRtpQKN/GQGq17oIQm8aK
kOdPt93g93ojMIg7YJpgDgOirvVz/hDn7YD4ryrtPos9CMafFkJprymKpRHyvz7P
8a3+OkuPjFjPnwOHQ5u1U3+8vC44vfb1ExWzDLoT8Xp8Gndx39k0f7MVOol3GnYu
MN/dvNUdAgMBAAGjSzBJMA4GA1UdDwEB/wQEAwIAoDATBgNVHSUEDDAKBggrBgEF
BQcDATAMBgNVHRMBAf8EAjAAMBQGA1UdEQQNMAuCCWxvY2FsaG9zdDALBgkqhkiG
9w0BAQUDggEBAIG8CJqvTIgJnNOK+i5/IUc/3yF/mSCWuG8qP+Fmo2t6T0PVOtc0
8wiWH5iWtCAhjn0MRY9l/hIjWm6gUZGHCGuEgsOPpJDYGoNLjH9Xwokm4y3LFNRK
UBrrrDbKRNibApBHCapPf6gC5sXcjOwx7P2/kiHDgY7YH47jfcRhtAPNsM4gjsEO
RmwENY+hRUFHIRfQTyalqND+x6PWhRo3K6hpHs4DQEYPq4P2kFPqUqSBymH+Ny5/
BcQ3wdMNmC6Bm/oiL1QV0M+/InOsAgQk/EDd0kmoU1ZT2lYHQduGmP099bOlHNpS
uqO3vXF3q8SPPr/A9TqSs7BKkBQbe0+cdsA=
-----END CERTIFICATE-----`

	rawKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA3HDTtcZneJVkn3f9P0EtxPd3GCFh8PN9YvyCsYoHUQ/1zGaJ
y3RB8sFupTol2s2j/Hugqjxkpp5dMeZP93bxgjI9iQlcTOvs+zaS/gIsL15r5I/0
znIgoMKrLAsGEtgolcI32s0Y8dWVCVQwuaoskbH5LUNn1R66ZyRlUkWoJokIMBlg
YpVRvQfEL0baUCjfxkBqte6CEJvGipDnT7fd4Pd6IzCIO2CaYA4Doq71c/4Q5+2A
+K8q7T6LPQjGnxZCaa8piqUR8r8+z/Gt/jpLj4xYz58Dh0ObtVN/vLwuOL329RMV
swy6E/F6fBp3cd/ZNH+zFTqJdxp2LjDf3bzVHQIDAQABAoIBAHal26147nQ+pHwY
jxwers3XDCjWvup7g79lfcqlKi79UiUEA6KYHm7UogMYewt7p4nb2KwH+XycvDiB
aAUf5flXpTs+6IkWauUDiLZi4PlV7uiEexUq5FjirlL0U/6MjbudX4bK4WQ4uxDc
WaV07Kw2iJFOOHLDKT0en9JaX5jtJNc4ZnE9efFoQ5jfypPWtRw65G1rULEg6nvc
GDh+1ce+4foCkpLRC9c24xAwJONZG6x3UqrSS9qfAsb73nWRQrTfUcO3nhoN8VvL
kL9skn1+S06NyUN0KoEtyRBp+RcpXSsBWAo6qZmo/WqhB/gjzWrxVwn20+yJSm35
ZsMc6QECgYEA8GS+Mp9xfB2szWHz6YTOO1Uu4lHM1ccZMwS1G+dL0KO3uGAiPdvp
woVot6v6w88t7onXsLo5pgz7SYug0CpkF3K/MRd1Ar4lH7PK7IBQ6rFr9ppVxDbx
AEWRswUoPbKCr7W6HU8LbQHDavsDlEIwc6+DiwnL4BzlKjb7RpgQEz0CgYEA6sB5
uHvx3Y5FDcGk1n73leQSAcq14l3ZLNpjrs8msoREDil/j5WmuSN58/7PGMiMgHEi
1vLm3H796JmvGr9OBvspOjHyk07ui2/We/j9Hoxm1VWhyi8HkLNDj70HKalTTFMz
RHO4O+0xCva+h9mKZrRMVktXr2jjdFn/0MYIZ2ECgYAIIsC1IeRLWQ3CHbCNlKsO
IwHlMvOFwKk/qsceXKOaOhA7szU1dr3gkXdL0Aw6mEZrrkqYdpUA46uVf54/rU+Z
445I8QxKvXiwK/uQKX+TkdGflPWWIG3jnnch4ejMvb/ihnn4B/bRB6A/fKNQXzUY
lTYUfI5j1VaEKTwz1W2l2QKBgByFCcSp+jZqhGUpc3dDsZyaOr3Q/Mvlju7uEVI5
hIAHpaT60a6GBd1UPAqymEJwivFHzW3D0NxU6VAK68UaHMaoWNfjHY9b9YsnKS2i
kE3XzN56Ks+/avHfdYPO+UHMenw5V28nh+hv5pdoZrlmanQTz3pkaOC8o3WNQZEB
nh/BAoGBAMY5z2f1pmMhrvtPDSlEVjgjELbaInxFaxPLR4Pdyzn83gtIIU14+R8X
2LPs6PPwrNjWnIgrUSVXncIFL3pa45B+Mx1pYCpOAB1+nCZjIBQmpeo4Y0dwA/XH
85EthKPvoszm+OPbyI16OcePV5ocX7lupRYuAo0pek7bomhmHWHz
-----END RSA PRIVATE KEY-----`
)

var (
	serverConfig = &gosocks5.Config{
		SelectMethod:   serverSelectMethod,
		MethodSelected: serverMethodSelected,
	}
)

type Socks5Server struct {
	Addr string // TCP address to listen on
}

func (s *Socks5Server) ListenAndServe() error {
	addr, err := net.ResolveTCPAddr("tcp", s.Addr)
	if err != nil {
		return err
	}

	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			log.Println("accept:", err)
			continue
		}
		//log.Println("accept", conn.RemoteAddr())

		go serveSocks5(gosocks5.ServerConn(conn, serverConfig))
	}
}

func serverSelectMethod(methods ...uint8) uint8 {
	//log.Println(methods)
	m := gosocks5.MethodNoAuth

	for _, method := range methods {
		if _, ok := Methods[method]; ok {
			m = method
		}
	}

	// when user/pass is set for proxy auth, the NoAuth method is disabled
	if len(Method) == 0 && m == gosocks5.MethodNoAuth && listenUrl.User != nil {
		return gosocks5.MethodNoAcceptable
	}

	if len(Method) == 0 || Methods[m] == Method {
		return m
	}

	return gosocks5.MethodNoAcceptable
}

func serverMethodSelected(method uint8, conn net.Conn) (net.Conn, error) {
	//log.Println(method)
	switch method {
	case gosocks5.MethodUserPass:
		var username, password string

		if listenUrl != nil && listenUrl.User != nil {
			username = listenUrl.User.Username()
			password, _ = listenUrl.User.Password()
		}

		if err := serverSocksAuth(conn, username, password); err != nil {
			return nil, err
		}
	case MethodTLS, MethodTLSAuth:
		var cert tls.Certificate
		var err error

		if len(CertFile) == 0 || len(KeyFile) == 0 {
			cert, err = tls.X509KeyPair([]byte(rawCert), []byte(rawKey))
		} else {
			cert, err = tls.LoadX509KeyPair(CertFile, KeyFile)
		}

		if err != nil {
			return nil, err
		}
		conn = tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}})
		if method == MethodTLSAuth {
			// password is mandatory
			if len(Password) == 0 {
				return nil, ErrEmptyAuth
			}
			if err := serverSocksAuth(conn, "", Password); err != nil {
				return nil, err
			}
		}
	case MethodAES128, MethodAES192, MethodAES256,
		MethodDES, MethodBF, MethodCAST5, MethodRC4MD5, MethodRC4, MethodTable:
		cipher, err := shadowsocks.NewCipher(Methods[method], Password)
		if err != nil {
			return nil, err
		}
		conn = shadowsocks.NewConn(conn, cipher)
	case gosocks5.MethodNoAcceptable:
		return nil, gosocks5.ErrBadMethod
	}

	return conn, nil
}

func serveSocks5(conn net.Conn) {
	defer conn.Close()

	req, err := gosocks5.ReadRequest(conn)
	if err != nil {
		log.Println(err)
		return
	}

	switch req.Cmd {
	case gosocks5.CmdConnect:
		//log.Println("connect", req.Addr.String())
		tconn, err := connect(req.Addr.String())
		if err != nil {
			log.Println("connect", req.Addr.String(), err)
			gosocks5.NewReply(gosocks5.HostUnreachable, nil).Write(conn)
			return
		}
		defer tconn.Close()

		rep := gosocks5.NewReply(gosocks5.Succeeded, nil)
		if err := rep.Write(conn); err != nil {
			return
		}

		if err := Transport(conn, tconn); err != nil {
			//log.Println(err)
		}
	case gosocks5.CmdBind:
		l, err := net.ListenTCP("tcp", nil)
		if err != nil {
			gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
			log.Println("bind listen", err)
			return
		}

		addr := ToSocksAddr(l.Addr())
		addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		log.Println("bind:", addr)
		rep := gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			log.Println(err)
			l.Close()
			return
		}

		tconn, err := l.AcceptTCP()
		l.Close() // only accept one peer
		if err != nil {
			log.Println("accept:", err)
			gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
			return
		}
		defer tconn.Close()

		addr = ToSocksAddr(tconn.RemoteAddr())
		log.Println("accept peer:", addr.String())
		rep = gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			log.Println(err)
			return
		}

		if err := Transport(conn, tconn); err != nil {
			//log.Println(err)
		}
	case gosocks5.CmdUdp:
		uconn, err := net.ListenUDP("udp", nil)
		if err != nil {
			log.Println("udp listen", err)
			gosocks5.NewReply(gosocks5.Failure, nil).Write(conn)
			return
		}
		defer uconn.Close()

		addr := ToSocksAddr(uconn.LocalAddr())
		addr.Host, _, _ = net.SplitHostPort(conn.LocalAddr().String())
		log.Println("udp:", addr)
		rep := gosocks5.NewReply(gosocks5.Succeeded, addr)
		if err := rep.Write(conn); err != nil {
			log.Println(err)
			return
		}
		srvTunnelUDP(conn, uconn)
	}
}

func srvTunnelUDP(conn net.Conn, uconn *net.UDPConn) {
	go func() {
		b := lpool.Take()
		defer lpool.put(b)

		for {
			n, addr, err := uconn.ReadFromUDP(b)
			if err != nil {
				log.Println(err)
				return
			}

			udp := gosocks5.NewUDPDatagram(
				gosocks5.NewUDPHeader(uint16(n), 0, ToSocksAddr(addr)), b[:n])
			//log.Println("r", udp.Header)
			if err := udp.Write(conn); err != nil {
				log.Println(err)
				return
			}
		}
	}()

	for {
		udp, err := gosocks5.ReadUDPDatagram(conn)
		if err != nil {
			log.Println(err)
			return
		}
		//log.Println("w", udp.Header)
		addr, err := net.ResolveUDPAddr("udp", udp.Header.Addr.String())
		if err != nil {
			log.Println(err)
			continue // drop silently
		}

		if _, err := uconn.WriteToUDP(udp.Data, addr); err != nil {
			log.Println(err)
			return
		}
	}
}
