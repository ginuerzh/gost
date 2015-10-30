package main

import (
	"crypto/tls"
	"fmt"
	"github.com/golang/glog"
	"io"
	"net"
	"net/url"
	"strings"
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

func init() {
	var err error
	if cert, err = tls.LoadX509KeyPair("cert.pem", "key.pem"); err != nil {
		glog.V(LWARNING).Infoln(err)

		cert, err = tls.X509KeyPair([]byte(rawCert), []byte(rawKey))
		if err != nil {
			glog.Infoln(err)
		}
	}
}

var (
	cert tls.Certificate
)

type strSlice []string

func (ss *strSlice) String() string {
	return fmt.Sprintf("%s", *ss)
}
func (ss *strSlice) Set(value string) error {
	*ss = append(*ss, value)
	return nil
}

// admin:123456@localhost:8080
type Args struct {
	Addr      string // host:port
	Protocol  string // protocol: http&socks5/http/socks/socks5/ss, default is http&socks5
	Transport string // transport: tcp/ws/tls, default is tcp(raw tcp)
	User      *url.Userinfo
	Cert      tls.Certificate // tls certificate
}

func (args Args) String() string {
	var authUser, authPass string
	if args.User != nil {
		authUser = args.User.Username()
		authPass, _ = args.User.Password()
	}
	return fmt.Sprintf("host: %s, protocol: %s, transport: %s, auth: %s:%s",
		args.Addr, args.Protocol, args.Transport, authUser, authPass)
}

func parseArgs(ss []string) (args []Args) {
	for _, s := range ss {
		if !strings.Contains(s, "://") {
			s = "tcp://" + s
		}
		u, err := url.Parse(s)
		if err != nil {
			glog.V(LWARNING).Infoln(err)
			continue
		}

		arg := Args{
			Addr: u.Host,
			User: u.User,
			Cert: cert,
		}

		schemes := strings.Split(u.Scheme, "+")
		if len(schemes) == 1 {
			arg.Protocol = schemes[0]
			arg.Transport = schemes[0]
		}
		if len(schemes) == 2 {
			arg.Protocol = schemes[0]
			arg.Transport = schemes[1]
		}

		switch arg.Protocol {
		case "http", "socks", "socks5", "ss":
		default:
			arg.Protocol = "default"
		}
		switch arg.Transport {
		case "ws", "tls", "tcp":
		default:
			arg.Transport = "tcp"
		}

		args = append(args, arg)
	}

	return
}

// based on io.Copy
func Copy(dst io.Writer, src io.Reader) (written int64, err error) {
	buf := make([]byte, 32*1024)

	for {
		nr, er := src.Read(buf)
		//log.Println("cp r", nr, er)
		if nr > 0 {
			nw, ew := dst.Write(buf[:nr])
			//log.Println("cp w", nw, ew)
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			/*
				if nr != nw {
					err = io.ErrShortWrite
					break
				}
			*/
		}
		if er == io.EOF {
			break
		}
		if er != nil {
			err = er
			break
		}
	}
	return
}

func Pipe(src io.Reader, dst io.Writer, ch chan<- error) {
	_, err := Copy(dst, src)
	ch <- err
}

func Transport(conn, conn2 net.Conn) (err error) {
	rChan := make(chan error, 1)
	wChan := make(chan error, 1)

	go Pipe(conn, conn2, wChan)
	go Pipe(conn2, conn, rChan)

	select {
	case err = <-wChan:
		//log.Println("w exit", err)
	case err = <-rChan:
		//log.Println("r exit", err)
	}

	return
}
