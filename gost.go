package gost

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/golang/glog"
)

const (
	Version = "2.4-dev20170711"
)

// Log level for glog
const (
	LFATAL = iota
	LERROR
	LWARNING
	LINFO
	LDEBUG
)

var Debug bool

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
	defaultRawCert []byte
	defaultRawKey  []byte
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

func generateKeyPair() (rawCert, rawKey []byte) {
	if defaultRawCert != nil && defaultRawKey != nil {
		return defaultRawCert, defaultRawKey
	}

	// Create private key and self-signed certificate
	// Adapted from https://golang.org/src/crypto/tls/generate_cert.go

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		glog.Fatal(err)
	}
	validFor := time.Hour * 24 * 365 * 10
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"gost"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		glog.Fatal(err)
	}

	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return rawCert, rawKey
}

// Load the certificate from cert and key files, will use the default certificate if the provided info are invalid.
func LoadCertificate(certFile, keyFile string) (tls.Certificate, error) {
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err == nil {
		return tlsCert, nil
	}
	glog.V(LWARNING).Infoln(err)

	rawCert, rawKey := defaultRawCert, defaultRawKey
	if defaultRawCert == nil || defaultRawKey == nil {
		rawCert, rawKey = generateKeyPair()
	}
	return tls.X509KeyPair(rawCert, rawKey)
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
