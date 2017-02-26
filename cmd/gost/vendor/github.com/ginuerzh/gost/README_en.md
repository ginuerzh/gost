gost - GO Simple Tunnel
======

### A simple security tunnel written in Golang

Features
------
* Listening on multiple ports
* Multi-level forward proxy - proxy chain
* Standard HTTP/HTTPS/SOCKS4(A)/SOCKS5 proxy protocols support
* TLS encryption via negotiation support for SOCKS5 proxy
* Tunnel UDP over TCP
* Shadowsocks protocol support (OTA: 2.2+, UDP: 2.4+)
* Local/remote port forwarding (2.1+)
* HTTP 2.0 support (2.2+)
* Experimental QUIC support (2.3+)
* KCP protocol support (2.3+)
* Transparent proxy (2.3+)
* SSH tunnel (2.4+)

Binary file download：https://github.com/ginuerzh/gost/releases

Google group: https://groups.google.com/d/forum/go-gost

Gost and other proxy services are considered to be proxy nodes, 
gost can handle the request itself, or forward the request to any one or more proxy nodes.

Parameter Description
------
#### Proxy and proxy chain

Effective for the -L and -F parameters

```bash
[scheme://][user:pass@host]:port
```
scheme can be divided into two parts: protocol+transport

protocol: proxy protocol types (http, socks4(a), socks5, shadowsocks), 
transport: data transmission mode (ws, wss, tls, http2, quic, kcp, pht), may be used in any combination or individually:

> http - standard HTTP proxy: http://:8080

> http+tls - standard HTTPS proxy (may need to provide a trusted certificate): http+tls://:443 or https://:443

> http2 - HTTP2 proxy and backwards-compatible with HTTPS proxy: http2://:443

> socks4(a) - standard SOCKS4(A) proxy: socks4://:1080 or socks4a://:1080

> socks - standard SOCKS5 proxy: socks://:1080

> socks+wss - SOCKS5 over websocket: socks+wss://:1080

> tls - HTTPS/SOCKS5 over TLS: tls://:443

> ss - standard shadowsocks proxy, ss://chacha20:123456@:8338

> ssu - shadowsocks UDP relay，ssu://chacha20:123456@:8338

> quic - standard QUIC proxy, quic://:6121

> kcp - standard KCP tunnel，kcp://:8388 or kcp://aes:123456@:8388

> pht - plain HTTP tunnel, pht://:8080

> redirect - transparent proxy，redirect://:12345

> ssh - SSH tunnel, ssh://admin:123456@:2222

#### Port forwarding

Effective for the -L parameter

```bash
scheme://[bind_address]:port/[host]:hostport
```	
> scheme - forward mode, local: tcp, udp; remote: rtcp, rudp

> bind_address:port - local/remote binding address

> host:hostport - target address

#### Configuration file

> -C : specifies the configuration file path

The configuration file is in standard JSON format:
```json
{
    "ServeNodes": [
        ":8080",
        "ss://chacha20:12345678@:8338"
    ],
    "ChainNodes": [
        "http://192.168.1.1:8080",
        "https://10.0.2.1:443"
    ]
}
```

ServeNodes is equivalent to the -L parameter, ChainNodes is equivalent to the -F parameter.

#### Logging

> -logtostderr : log to console

> -v=3 : log level (1-5)，The higher the level, the more detailed the log (level 5 will enable HTTP2 debug)

> -log_dir=/log/dir/path : log to directory /log/dir/path

Usage
------
#### No forward proxy

<img src="https://ginuerzh.github.io/images/gost_01.png" />

* Standard HTTP/SOCKS5 proxy
```bash
gost -L=:8080
```

* Proxy authentication
```bash
gost -L=admin:123456@localhost:8080
```

* Multiple sets of authentication information
```bash
gost -L=localhost:8080?secrets=secrets.txt
```

The secrets parameter allows you to set multiple authentication information for HTTP/SOCKS5 proxies, the format is:
```plain
# username password

test001 123456
test002 12345678
```

* Listen on multiple ports
```bash
gost -L=http2://:443 -L=socks://:1080 -L=ss://aes-128-cfb:123456@:8338
```

#### Forward proxy

<img src="https://ginuerzh.github.io/images/gost_02.png" />
```bash
gost -L=:8080 -F=192.168.1.1:8081
```

* Forward proxy authentication
```bash
gost -L=:8080 -F=http://admin:123456@192.168.1.1:8081
```

#### Multi-level forward proxy

<img src="https://ginuerzh.github.io/images/gost_03.png" />
```bash
gost -L=:8080 -F=http+tls://192.168.1.1:443 -F=socks+ws://192.168.1.2:1080 -F=ss://aes-128-cfb:123456@192.168.1.3:8338 -F=a.b.c.d:NNNN
```
Gost forwards the request to a.b.c.d:NNNN through the proxy chain in the order set by -F, 
each forward proxy can be any HTTP/HTTPS/HTTP2/SOCKS5/Shadowsocks type.

#### Local TCP port forwarding

```bash
gost -L=tcp://:2222/192.168.1.1:22 -F=...
```
The data on the local TCP port 2222 is forwarded to 192.168.1.1:22 (through the proxy chain). If the last node of the chain (the last -F parameter) is a SSH tunnel, then gost will use the local port forwarding function of SSH directly.

#### Local UDP port forwarding

```bash
gost -L=udp://:5353/192.168.1.1:53?ttl=60 -F=...
```
The data on the local UDP port 5353 is forwarded to 192.168.1.1:53 (through the proxy chain). 
Each forwarding channel has a timeout period. When this time is exceeded and there is no data interaction during this time period, the channel will be closed. The timeout value can be set by the `ttl` parameter. The default value is 60 seconds.

**NOTE:** When forwarding UDP data, if there is a proxy chain, the end of the chain (the last -F parameter) must be gost SOCKS5 proxy.

#### Remote TCP port forwarding

```bash
gost -L=rtcp://:2222/192.168.1.1:22 -F=... -F=socks://172.24.10.1:1080
```
The data on 172.24.10.1:2222 is forwarded to 192.168.1.1:22 (through the proxy chain). If the last node of the chain (the last -F parameter) is a SSH tunnel, then gost will use the remote port forwarding function of SSH directly.

#### Remote UDP port forwarding

```bash
gost -L=rudp://:5353/192.168.1.1:53 -F=... -F=socks://172.24.10.1:1080
```
The data on 172.24.10.1:5353 is forwarded to 192.168.1.1:53 (through the proxy chain).

**NOTE:** To use the remote port forwarding feature, the proxy chain can not be empty (at least one -F parameter is set) 
and the end of the chain (last -F parameter) must be gost SOCKS5 proxy.

#### HTTP2
Gost HTTP2 supports two modes and self-adapting:
* As a standard HTTP2 proxy, and backwards-compatible with the HTTPS proxy.
* As transport (similar to wss), tunnel other protocol.

Server:
```bash
gost -L=http2://:443
```
Client:
```bash
gost -L=:8080 -F=http2://server_ip:443?ping=30
```

The client supports the `ping` parameter to enable heartbeat detection (which is disabled by default). 
Parameter value represents heartbeat interval seconds.

**NOTE:** The proxy chain of gost supports only one HTTP2 proxy node and the nearest rule applies, 
the first HTTP2 proxy node is treated as an HTTP2 proxy, and the other HTTP2 proxy nodes are treated as HTTPS proxies.

#### QUIC
Support for QUIC is based on library [quic-go](https://github.com/lucas-clemente/quic-go).

Server:
```bash
gost -L=quic://:6121
```
Client(Chrome):
```bash
chrome --enable-quic --proxy-server=quic://server_ip:6121
```

**NOTE:** Due to Chrome's limitations, it is currently only possible to access the HTTP (but not HTTPS) site through QUIC.

#### KCP
Support for KCP is based on libraries [kcp-go](https://github.com/xtaci/kcp-go) and [kcptun](https://github.com/xtaci/kcptun).

Server:
```bash
gost -L=kcp://:8388
```
Client:
```bash
gost -L=:8080 -F=kcp://server_ip:8388
```

Or manually specify the encryption method and password (Manually specifying the encryption method and password overwrites the corresponding value in the configuration file)

Server:
```bash
gost -L=kcp://aes:123456@:8388
```

Client:
```bash
gost -L=:8080 -F=kcp://aes:123456@server_ip:8388
```

Gost will automatically load kcp.json configuration file from current working directory if exists, 
or you can use the parameter to specify the path to the file.
```bash
gost -L=kcp://:8388?c=/path/to/conf/file
```

**NOTE:** KCP will be enabled if and only if the proxy chain is not empty and the first proxy node (the first -F parameter) is of type KCP.

#### Transparent proxy
Iptables-based transparent proxy

```bash
gost -L=redirect://:12345 -F=http2://server_ip:443
```

Encryption Mechanism
------
#### HTTP
For HTTP, you can use TLS to encrypt the entire communication process, the HTTPS proxy:

Server:
```bash
gost -L=http+tls://:443
```
Client:
```bash
gost -L=:8080 -F=http+tls://server_ip:443
```

#### HTTP2
Gost supports only the HTTP2 protocol that uses TLS encryption (h2) and does not support plaintext HTTP2 (h2c) transport.


#### SOCKS5
Gost supports the standard SOCKS5 protocol methods: no-auth (0x00) and user/pass (0x02), 
and extends two methods for data encryption: tls(0x80) and tls-auth(0x82).

Server:
```bash
gost -L=socks://:1080
```
Client:
```bash
gost -L=:8080 -F=socks://server_ip:1080
```

If both ends are gosts (as example above), the data transfer will be encrypted (using tls or tls-auth). 
Otherwise, use standard SOCKS5 for communication (no-auth or user/pass).

**NOTE:** If transport already supports encryption (wss, tls, http2, kcp), SOCKS5 will no longer use the encryption method to prevent unnecessary double encryption.

#### Shadowsocks
Support for shadowsocks is based on library [shadowsocks-go](https://github.com/shadowsocks/shadowsocks-go).

Server (The OTA mode can be enabled by the ota parameter. When enabled, the client must use OTA mode):
```bash
gost -L=ss://aes-128-cfb:123456@:8338?ota=1
```
Client (The OTA mode can be enabled by the ota parameter):
```bash
gost -L=:8080 -F=ss://aes-128-cfb:123456@server_ip:8338?ota=1
```

##### Shadowsocks UDP relay
Currently, only the server supports UDP, and only OTA mode is supported.

Server:
```bash
gost -L=ssu://aes-128-cfb:123456@:8338
```

#### TLS
There is built-in TLS certificate in gost, if you need to use other TLS certificate, there are two ways:
* Place two files cert.pem (public key) and key.pem (private key) in the current working directory, gost will automatically load them.
* Use the parameter to specify the path to the certificate file:
```bash
gost -L="http2://:443?cert=/path/to/my/cert/file&key=/path/to/my/key/file"
```

SOCKS5 UDP Data Processing
------
#### No forward proxy

<img src="https://ginuerzh.github.io/images/udp01.png" height=100 />

Gost acts as the standard SOCKS5 proxy for UDP relay.

#### Forward proxy

<img src="https://ginuerzh.github.io/images/udp02.png" height=100 />

#### Multi-level forward proxy

<img src="https://ginuerzh.github.io/images/udp03.png" height=200 />

When forward proxies are set, gost uses UDP-over-TCP to forward UDP data, proxy1 to proxyN can be any HTTP/HTTPS/HTTP2/SOCKS5/Shadowsocks type.

Limitation
------
The HTTP proxy node in the proxy chain must support the CONNECT method.

If the BIND and UDP requests for SOCKS5 are to be forwarded, the end of the chain (the last -F parameter) must be the gost SOCKS5 proxy.



