package gost

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"github.com/golang/glog"
	"io"
	"net"
	"strings"
	"time"
)

const (
	Version = "2.4-dev20170303"
)

// Log level for glog
const (
	LFATAL = iota
	LERROR
	LWARNING
	LINFO
	LDEBUG
)

var (
	KeepAliveTime = 180 * time.Second
	DialTimeout   = 30 * time.Second
	ReadTimeout   = 90 * time.Second
	WriteTimeout  = 90 * time.Second

	DefaultTTL = 60 // default udp node TTL in second for udp port forwarding
)

var (
	SmallBufferSize  = 1 * 1024  // 1KB small buffer
	MediumBufferSize = 8 * 1024  // 8KB medium buffer
	LargeBufferSize  = 32 * 1024 // 32KB large buffer
)

var (
	DefaultCertFile = "cert.pem"
	DefaultKeyFile  = "key.pem"

	// This is the default cert and key data for convenience, providing your own cert is recommended.
	defaultRawCert = []byte(`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`)
	defaultRawKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`)
)

var (
	ErrEmptyChain = errors.New("empty chain")
)

func setKeepAlive(conn net.Conn, d time.Duration) error {
	c, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("Not a TCP connection")
	}
	if err := c.SetKeepAlive(true); err != nil {
		return err
	}
	if err := c.SetKeepAlivePeriod(d); err != nil {
		return err
	}
	return nil
}

// Load the certificate from cert and key files, will use the default certificate if the provided info are invalid.
func LoadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		return tlsCert, nil
	}
	glog.V(LWARNING).Infoln(err)
	return tls.X509KeyPair(defaultRawCert, defaultRawKey)
}

// Replace the default certificate by your own
func SetDefaultCertificate(rawCert, rawKey []byte) {
	defaultRawCert = rawCert
	defaultRawKey = rawKey
}

func basicProxyAuth(proxyAuth string) (username, password string, ok bool) {
	if proxyAuth == "" {
		return
	}

	if !strings.HasPrefix(proxyAuth, "Basic ") {
		return
	}
	c, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, "Basic "))
	if err != nil {
		return
	}
	cs := string(c)
	s := strings.IndexByte(cs, ':')
	if s < 0 {
		return
	}

	return cs[:s], cs[s+1:], true
}

func Transport(rw1, rw2 io.ReadWriter) error {
	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(rw1, rw2)
		errc <- err
	}()

	go func() {
		_, err := io.Copy(rw2, rw1)
		errc <- err
	}()

	return <-errc
}
