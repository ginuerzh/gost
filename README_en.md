gost - GO Simple Tunnel
======

### A simple security tunnel written in Golang

Features
------
* Listening on multiple ports
* Multi-level forward proxy - proxy chain
* Standard HTTP/HTTPS/SOCKS5 proxy protocols
* TLS encryption via negotiation support for SOCKS5 proxy
* Tunnel UDP over TCP
* Shadowsocks protocol with OTA supported (OTA: >=2.2)
* Local/Remote port forwarding (>=2.1)
* HTTP2.0 (>=2.2)
* Experimental QUIC support (>=2.3)

Binary file download：https://github.com/ginuerzh/gost/releases

Google group: https://groups.google.com/d/forum/go-gost

Gost and other proxy services are considered to be proxy nodes, gost can handle the request itself, or forward the request to any one or more proxy nodes.

Parameter Description
------
#### Proxy and proxy chain

Effective for the -L and -F parameters

```bash
[scheme://][user:pass@host]:port
```
scheme can be divided into two parts: protocol+transport

protocol: proxy protocol types(http, socks5, shadowsocks), transport: data transmission mode(ws, wss, tls, http2, quic), may be used in any combination or individually:

> http - standard HTTP proxy: http://:8080

> http+tls - standard HTTPS proxy(may need to provide a trusted certificate): http+tls://:443

> http2 - HTTP2 proxy and downwards compatible HTTPS proxy: http2://:443

> socks - standard SOCKS5 proxy: socks://:1080

> socks+ws - SOCKS5 protocol over websocket: socks+ws://:1080

> tls - HTTPS/SOCKS5 over tls: tls://:443

> ss - shadowsocks proxy, ss://aes-256-cfb:123456@:8338

> quic - QUIC proxy, quic://:6121

#### Port forwarding

Effective for the -L parameter

```bash
scheme://[bind_address]:port/[host]:hostport
```	
> scheme - forward mode, local: tcp, udp; remote: rtcp, rudp

> bind_address:port - local/remote binding address

> host:hostport - target address

#### 开启日志

> -logtostderr : log to console

> -v=4 : log level(1-5)，The higher the level, the more detailed the log (level 5 will enable HTTP2 debug)

> -log_dir=. : log to dir


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
gost按照-F设置顺序通过代理链将请求最终转发给a.b.c.d:NNNN处理，每一个转发代理可以是任意HTTP/HTTPS/HTTP2/SOCKS5/Shadowsocks类型代理。

#### 本地端口转发(TCP)

```bash
gost -L=tcp://:2222/192.168.1.1:22 -F=...
```
将本地TCP端口2222上的数据(通过代理链)转发到192.168.1.1:22上。

#### 本地端口转发(UDP)

```bash
gost -L=udp://:5353/192.168.1.1:53 -F=...
```
将本地UDP端口5353上的数据(通过代理链)转发到192.168.1.1:53上。

**注: 转发UDP数据时，如果有代理链，则代理链的末端(最后一个-F参数)必须支持gost SOCKS5类型代理。**

#### 远程端口转发(TCP)

```bash
gost -L=rtcp://:2222/192.168.1.1:22 -F=... -F=socks://172.24.10.1:1080
```
将172.24.10.1:2222上的数据(通过代理链)转发到192.168.1.1:22上。

#### 远程端口转发(UDP)

```bash
gost -L=rudp://:5353/192.168.1.1:53 -F=... -F=socks://172.24.10.1:1080
```
将172.24.10.1:5353上的数据(通过代理链)转发到192.168.1.1:53上。

**注: 若要使用远程端口转发功能，代理链不能为空(至少要设置一个-F参数)，且代理链的末端(最后一个-F参数)必须支持gost SOCKS5类型代理。**

#### HTTP2
gost的HTTP2支持两种模式并自适应：
* 作为标准的HTTP2代理，并向下兼容HTTPS代理。
* 作为transport(类似于wss)，传输其他协议。

**注：gost的代理链仅支持一个HTTP2代理节点，采用就近原则，会将第一个遇到的HTTP2代理节点视为HTTP2代理，其他HTTP2代理节点则被视为HTTPS代理。**

加密机制
------
#### HTTP
对于HTTP可以使用TLS加密整个通讯过程，即HTTPS代理：

服务端:
```bash
gost -L=http+tls://:443
```
客户端:
```bash
gost -L=:8080 -F=http+tls://server_ip:443
```

#### HTTP2
gost仅支持使用TLS加密的HTTP2协议，不支持明文HTTP2传输。

服务端:
```bash
gost -L=http2://:443
```
客户端:
```bash
gost -L=:8080 -F=http2://server_ip:443
```

#### SOCKS5
gost支持标准SOCKS5协议的no-auth(0x00)和user/pass(0x02)方法，并在此基础上扩展了两个：tls(0x80)和tls-auth(0x82)，用于数据加密。

服务端:
```bash
gost -L=socks://:1080
```
客户端:
```bash
gost -L=:8080 -F=socks://server_ip:1080
```

如果两端都是gost(如上)则数据传输会被加密(协商使用tls或tls-auth方法)，否则使用标准SOCKS5进行通讯(no-auth或user/pass方法)。

注：如果transport已经支持加密(wss, tls, http2)，则SOCKS5不会再使用加密方法，防止不必要的双重加密。

#### Shadowsocks
gost对Shadowsocks加密方法的支持是基于[shadowsocks-go](https://github.com/shadowsocks/shadowsocks-go)库。

服务端(可以通过ota参数开启OTA模式):
```bash
gost -L=ss://aes-128-cfb:123456@:8338?ota=1
```
客户端:
```bash
gost -L=:8080 -F=ss://aes-128-cfb:123456@server_ip:8338
```

#### TLS
gost内置了TLS证书，如果需要使用其他TLS证书，有两种方法：
* 在gost运行目录放置cert.pem(公钥)和key.pem(私钥)两个文件即可，gost会自动加载运行目录下的cert.pem和key.pem文件。
* 使用参数指定证书文件路径：
```bash
gost -L="http2://:443?cert=/path/to/my/cert/file&key=/path/to/my/key/file"
```

SOCKS5 UDP数据处理
------
#### 不设置转发代理

<img src="https://ginuerzh.github.io/images/udp01.png" height=100 />

gost作为标准SOCKS5代理处理UDP数据

#### 设置转发代理

<img src="https://ginuerzh.github.io/images/udp02.png" height=100 />

#### 设置多个转发代理(代理链)

<img src="https://ginuerzh.github.io/images/udp03.png" height=200 />

当设置转发代理时，gost会使用UDP-over-TCP方式转发UDP数据。proxy1 - proxyN可以为任意HTTP/HTTPS/HTTP2/SOCKS5/Shadowsocks类型代理。

限制条件
------
代理链中的HTTP代理节点必须支持CONNECT方法。

如果要转发SOCKS5的BIND和UDP请求，代理链的末端(最后一个-F参数)必须支持gost SOCKS5类型代理。



