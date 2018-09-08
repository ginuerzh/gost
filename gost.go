package gost

import (
	"crypto/tls"
	"time"

	"github.com/go-log/log"
)

// Version is the gost version.
const Version = "2.5"

// Debug is a flag that enables the debug log.
var Debug bool

var (
	tinyBufferSize   = 128
	smallBufferSize  = 1 * 1024  // 1KB small buffer
	mediumBufferSize = 8 * 1024  // 8KB medium buffer
	largeBufferSize  = 32 * 1024 // 32KB large buffer
)

var (
	// KeepAliveTime is the keep alive time period for TCP connection.
	KeepAliveTime = 180 * time.Second
	// DialTimeout is the timeout of dial.
	DialTimeout = 30 * time.Second
	// ReadTimeout is the timeout for reading.
	ReadTimeout = 30 * time.Second
	// WriteTimeout is the timeout for writing.
	WriteTimeout = 60 * time.Second
	// PingTimeout is the timeout for pinging.
	PingTimeout = 30 * time.Second
	// PingRetries is the reties of ping.
	PingRetries = 1
	// default udp node TTL in second for udp port forwarding.
	defaultTTL = 60 * time.Second
)

var (
	// DefaultTLSConfig is a default TLS config for internal use
	DefaultTLSConfig = loadDefaultTLSConfig()

	// DefaultUserAgent is the default HTTP User-Agent header used by HTTP and websocket
	DefaultUserAgent = "Chrome/60.0.3112.90"
)

func loadDefaultTLSConfig() *tls.Config {
	rawCert := []byte(`
-----BEGIN CERTIFICATE-----
MIIC3TCCAcWgAwIBAgIQXkYunyWoxV0BydcC+nRKDjANBgkqhkiG9w0BAQsFADAP
MQ0wCwYDVQQKEwRnb3N0MB4XDTE4MDkwODExNTU1NVoXDTI4MDkwNTExNTU1NVow
DzENMAsGA1UEChMEZ29zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMauFs3lhmBdxbRM8xjz2Hl7oh6lHt2Fr6LQp788E4CECPiSuig0TT4APgvUcxDN
byk5GXDEh57TP9j5HwB7Zntpb1gWWiDF5kchTLJapdKy0gpdQTcq+TwR3b7maxgX
3ut9QpnMwJ2lYafdf/kG+3DBA0xhtzEFJKZDIfXIss+2UexCdEg+7JjOzfvG4FCM
0j7rMeOqMqYtZ0rAeB7WC/RlhXgzN2mAMLDmzFC6PBMqAnbSC9IE4plWvTHiVkga
7TnKYD0aFMadXVZHT8ah+9ElAlcc+ZtbfhTP37KzGLBTnwJ5qb4lr6mHnOmlvR2j
jv32cKaImsNYfd0OKS87LjsCAwEAAaM1MDMwDgYDVR0PAQH/BAQDAgWgMBMGA1Ud
JQQMMAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggEB
ABlEd77Tr7rfUv0GrompQVa7OQvkKzd0W8vKhBtSpSx+ri5bwbLyrdKtjz0/vZ1X
cVrWy4tQuKWCY522RB/1fqNgtuwTudJspXzmJvH0UuSLK6v5uoxm1tJAHv5I+EtW
P8lP5Zu83UfFdEgyQXAx3nepC8hUxhYh+UAiz4BK4xjbVK7jAJs64evEhxF8Cn7f
tyfQhU176+U44fM/KMDPixxWy/WypfuqLXNol/CvcZM8a2xIKyWsir2U16ZxmFQe
YDQjFti2Y5p1q+9+ig0pTEC+ZXRH52pGqFGAFi0Yo6yud0WcodbBjlURYNBSlOTx
9c/TL+KRNmaUN9Zgk+Qg+jI=
-----END CERTIFICATE-----
`)

	rawKey := []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxq4WzeWGYF3FtEzzGPPYeXuiHqUe3YWvotCnvzwTgIQI+JK6
KDRNPgA+C9RzEM1vKTkZcMSHntM/2PkfAHtme2lvWBZaIMXmRyFMslql0rLSCl1B
Nyr5PBHdvuZrGBfe631CmczAnaVhp91/+Qb7cMEDTGG3MQUkpkMh9ciyz7ZR7EJ0
SD7smM7N+8bgUIzSPusx46oypi1nSsB4HtYL9GWFeDM3aYAwsObMULo8EyoCdtIL
0gTimVa9MeJWSBrtOcpgPRoUxp1dVkdPxqH70SUCVxz5m1t+FM/fsrMYsFOfAnmp
viWvqYec6aW9HaOO/fZwpoiaw1h93Q4pLzsuOwIDAQABAoIBAH6W26bS0LzD4r1P
rjC+5bX5xUEbWkAw9siZg9hAEfj3p7Oh4YTOVkzj4KSu96XED0jHveLxBax30x2P
FWa8OX72neAVVdW94kx99h1JzpAiKdw6sNvSwLy6cXw52hCe3QVUaUQPhsarYj6P
zgNApKKiCFT5ibxtF33sFk5BU1UuKS1JSCE+86dBcD7IGnJpWtv6sYDLuBq8M6kH
nlL66nkpexrrfV616XPHrwiiL4fPJ8p0TWYQZ2Dh2WW4gNl7JcCwoGxe3QdEJVjX
sZe8qmfjc5bGzaaTljnBy/8Am2kQhO/mencBXPLP/4inOofH78ZJdfF6W49x257G
CiM7pFkCgYEA5l6txWc8BqQHjRJyOBN97MJTk3xZtpLezp6fKIQwflOapvpnNW8y
f7s/4pmVprp5/hMa86sn0PsedWvHMMDYV8J2i2ZTe2YLnv7hQ33K9kqr0YZZYlcK
a99QII604TJLCYlfJsKJtpvdohu2A6cea1ZRp9IrehjzTvvOzPoYmF8CgYEA3MjU
zsrMnIiVQSrnEcHR5OutZF+YLxVMMNKo8D5N8uHlDT3hcFwkSI/G9ZUfTDaXKmuy
YwlCcxtYoWIHahtHqi7K8ChM2NEnDy5Vu0O7QTXhRmHFciShuMjLl1XLkxffMHeR
foRIPv3N3eNVhIMRGAR0fdIZhieRyi3aUHvlp6UCgYAfAqO1rP3hjvcNQGxrrAQJ
eOczNUwGTaL8gVG/bHvypWJuE8sM4FkV5Kjm4fHJLdT6JKw+HM4RTZx+BfIcV/lH
Zv/6J94ZAFWUI49DPI2ztb2HSOSDXmAiwT7SAyPKJLEBKaLLXuiW0kh1Z/GKcFah
8E6xnpMHrpAiE7d01D23VQKBgFpBQzWSE9j9wL4WMsXAjPRfH8/DgGvm8fGXfHZR
kf3zOHaUUF9lW3PKStRD9LpsKpmt0wvHUkHJ8Q5wC4XlxwMcA9vvLZMI1UXQdD2M
b7U1uHTULSn/LZljhE7GROVJwfSHPJQSsZIGoSzO7TuxdMBzucdhpwt/i4qx+egi
7fv9AoGBAKAbV+R+CF8wtgVqj8o1EeTVVbDwMUikvur42eksPkWyEojiqDx7IzEN
DGIJ1GR7gAj6q1O3N7xEX9wKF8ZIY7w6kR0fiN+pSz10kmuHb+8PGRPj0uXgC5Fj
YEah2l9zr+XiG/WWfxSQcHK0lGfjtsyK8jDKCvTBObXIeaRufXFI
-----END RSA PRIVATE KEY-----
`)

	cert, err := tls.X509KeyPair(rawCert, rawKey)
	if err != nil {
		panic(err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

// SetLogger sets a new logger for internal log system
func SetLogger(logger log.Logger) {
	log.DefaultLogger = logger
}
