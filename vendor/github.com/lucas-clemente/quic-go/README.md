# A QUIC server implementation in pure Go

<img src="docs/quic.png" width=303 height=124>

[![Godoc Reference](https://img.shields.io/badge/godoc-reference-blue.svg?style=flat-square)](https://godoc.org/github.com/lucas-clemente/quic-go)
[![Linux Build Status](https://img.shields.io/travis/lucas-clemente/quic-go/master.svg?style=flat-square&label=linux+build)](https://travis-ci.org/lucas-clemente/quic-go)
[![Windows Build Status](https://img.shields.io/appveyor/ci/lucas-clemente/quic-go/master.svg?style=flat-square&label=windows+build)](https://ci.appveyor.com/project/lucas-clemente/quic-go/branch/master)
[![Code Coverage](https://img.shields.io/codecov/c/github/lucas-clemente/quic-go/master.svg?style=flat-square)](https://codecov.io/gh/lucas-clemente/quic-go/)

quic-go is an implementation of the [QUIC](https://en.wikipedia.org/wiki/QUIC) protocol in Go. While we're not far from being feature complete, there's still work to do regarding performance and security. At the moment, we do not recommend use in production systems. We appreciate any feedback :)

## Roadmap

Done:

- Basic protocol with support for QUIC version 34-36
- QUIC client
- HTTP/2 support
- Crypto (RSA / ECDSA certificates, Curve25519 for key exchange, AES-GCM or Chacha20-Poly1305 as stream cipher)
- Loss detection and retransmission (currently fast retransmission & RTO)
- Flow Control
- Congestion control using cubic

Major TODOs:

- Security, especially DoS protections
- Performance
- Better packet loss detection
- Connection migration

## Guides

Installing deps:

    go get -t

Running tests:

    go test ./...

### Running the example server

    go run example/main.go -www /var/www/

Using the `quic_client` from chromium:

    quic_client --host=127.0.0.1 --port=6121 --v=1 https://quic.clemente.io

Using Chrome:

    /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --user-data-dir=/tmp/chrome --no-proxy-server --enable-quic --origin-to-force-quic-on=quic.clemente.io:443 --host-resolver-rules='MAP quic.clemente.io:443 127.0.0.1:6121' https://quic.clemente.io

### Using the example client

    go run example/client/main.go https://quic.clemente.io

## Usage

### As a server

See the [example server](example/main.go) or try out [Caddy](https://github.com/mholt/caddy) (from version 0.9, [instructions here](https://github.com/mholt/caddy/wiki/QUIC)). Starting a QUIC server is very similar to the standard lib http in go:

```go
http.Handle("/", http.FileServer(http.Dir(wwwDir)))
h2quic.ListenAndServeQUIC("localhost:4242", "/path/to/cert/chain.pem", "/path/to/privkey.pem", nil)
```

### As a client

See the [example client](example/client/main.go). Use a `QuicRoundTripper` as a `Transport` in a `http.Client`.

```go
http.Client{
  Transport: &h2quic.QuicRoundTripper{},
}
```

## Building on Windows

Due to the low Windows timer resolution (see [StackOverflow question](http://stackoverflow.com/questions/37706834/high-resolution-timers-millisecond-precision-in-go-on-windows)) available with Go 1.6.x, some optimizations might not work when compiled with this version of the compiler. Please use Go 1.7 on Windows.
