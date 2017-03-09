gost - GO Simple Tunnel
======

### GO语言实现的安全隧道

[English README](README_en.md)

特性
------
* 可同时监听多端口
* 可设置转发代理，支持多级转发(代理链)
* 支持标准HTTP/HTTPS/SOCKS4(A)/SOCKS5代理协议
* SOCKS5代理支持TLS协商加密
* Tunnel UDP over TCP
* 支持Shadowsocks协议 (OTA: 2.2+，UDP: 2.4+)
* 支持本地/远程端口转发 (2.1+)
* 支持HTTP 2.0 (2.2+)
* 实验性支持QUIC (2.3+)
* 支持KCP协议 (2.3+)
* 透明代理 (2.3+)
* SSH隧道 (2.4+)

二进制文件下载：https://github.com/ginuerzh/gost/releases

Google讨论组: https://groups.google.com/d/forum/go-gost

在gost中，gost与其他代理服务都被看作是代理节点，gost可以自己处理请求，或者将请求转发给任意一个或多个代理节点。

参数说明
------
#### 代理及代理链

适用于-L和-F参数

```bash
[scheme://][user:pass@host]:port
```
scheme分为两部分: protocol+transport

protocol: 代理协议类型(http, socks4(a), socks5, shadowsocks), transport: 数据传输方式(ws, wss, tls, http2, quic, kcp, pht), 二者可以任意组合，或单独使用:

> http - HTTP代理: http://:8080

> http+tls - HTTPS代理(可能需要提供受信任的证书): http+tls://:443或https://:443

> http2 - HTTP2代理并向下兼容HTTPS代理: http2://:443

> socks4(a) - 标准SOCKS4(A)代理: socks4://:1080或socks4a://:1080

> socks - 标准SOCKS5代理(支持TLS协商加密): socks://:1080

> socks+wss - SOCKS5代理，使用websocket传输数据: socks+wss://:1080

> tls - HTTPS/SOCKS5代理，使用TLS传输数据: tls://:443

> ss - Shadowsocks代理，ss://chacha20:123456@:8338

> ssu - Shadowsocks UDP relay，ssu://chacha20:123456@:8338

> quic - QUIC代理，quic://:6121

> kcp - KCP通道，kcp://:8388或kcp://aes:123456@:8388

> pht - 普通HTTP通道，pht://:8080

> redirect - 透明代理，redirect://:12345

> ssh - SSH转发隧道，ssh://admin:123456@:2222

#### 端口转发

适用于-L参数

```bash
scheme://[bind_address]:port/[host]:hostport
```	
> scheme - 端口转发模式, 本地端口转发: tcp, udp; 远程端口转发: rtcp, rudp

> bind_address:port - 本地/远程绑定地址

> host:hostport - 目标访问地址

#### 配置文件

> -C : 指定配置文件路径

配置文件为标准json格式：
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

ServeNodes等同于-L参数，ChainNodes等同于-F参数

#### 开启日志

> -logtostderr : 输出到控制台

> -v=3 : 日志级别(1-5)，级别越高，日志越详细(级别5将开启http2 debug)

> -log_dir=/log/dir/path : 输出到目录/log/dir/path


使用方法
------
#### 不设置转发代理

<img src="https://ginuerzh.github.io/images/gost_01.png" />

* 作为标准HTTP/SOCKS5代理
```bash
gost -L=:8080
```

* 设置代理认证信息
```bash
gost -L=admin:123456@localhost:8080
```

* 多组认证信息
```bash
gost -L=localhost:8080?secrets=secrets.txt
```

通过secrets参数可以为HTTP/SOCKS5代理设置多组认证信息，格式为：
```plain
# username password

test001 123456
test002 12345678
```

* 多端口监听
```bash
gost -L=http2://:443 -L=socks://:1080 -L=ss://aes-128-cfb:123456@:8338
```

#### 设置转发代理

<img src="https://ginuerzh.github.io/images/gost_02.png" />
```bash
gost -L=:8080 -F=192.168.1.1:8081
```

* 转发代理认证
```bash
gost -L=:8080 -F=http://admin:123456@192.168.1.1:8081
```

#### 设置多级转发代理(代理链)

<img src="https://ginuerzh.github.io/images/gost_03.png" />
```bash
gost -L=:8080 -F=http+tls://192.168.1.1:443 -F=socks+ws://192.168.1.2:1080 -F=ss://aes-128-cfb:123456@192.168.1.3:8338 -F=a.b.c.d:NNNN
```
gost按照-F设置的顺序通过代理链将请求最终转发给a.b.c.d:NNNN处理，每一个转发代理可以是任意HTTP/HTTPS/HTTP2/SOCKS5/Shadowsocks类型代理。

#### 本地端口转发(TCP)

```bash
gost -L=tcp://:2222/192.168.1.1:22 -F=...
```
将本地TCP端口2222上的数据(通过代理链)转发到192.168.1.1:22上。当代理链末端(最后一个-F参数)为SSH类型时，gost会直接使用SSH的本地端口转发功能。
#### 本地端口转发(UDP)

```bash
gost -L=udp://:5353/192.168.1.1:53?ttl=60 -F=...
```
将本地UDP端口5353上的数据(通过代理链)转发到192.168.1.1:53上。
每条转发通道都有超时时间，当超过此时间，且在此时间段内无任何数据交互，则此通道将关闭。可以通过`ttl`参数来设置超时时间，默认值为60秒。

**注:** 转发UDP数据时，如果有代理链，则代理链的末端(最后一个-F参数)必须是gost SOCKS5类型代理。

#### 远程端口转发(TCP)

```bash
gost -L=rtcp://:2222/192.168.1.1:22 -F=... -F=socks://172.24.10.1:1080
```
将172.24.10.1:2222上的数据(通过代理链)转发到192.168.1.1:22上。当代理链末端(最后一个-F参数)为SSH类型时，gost会直接使用SSH的远程端口转发功能。

#### 远程端口转发(UDP)

```bash
gost -L=rudp://:5353/192.168.1.1:53 -F=... -F=socks://172.24.10.1:1080
```
将172.24.10.1:5353上的数据(通过代理链)转发到192.168.1.1:53上。

**注：** 若要使用远程端口转发功能，代理链不能为空(至少要设置一个-F参数)，且代理链的末端(最后一个-F参数)必须是gost SOCKS5类型代理。

#### HTTP2
gost的HTTP2支持两种模式并自适应：
* 作为标准的HTTP2代理，并向下兼容HTTPS代理。
* 作为transport(类似于wss)，传输其他协议。

服务端:
```bash
gost -L=http2://:443
```
客户端:
```bash
gost -L=:8080 -F=http2://server_ip:443?ping=30
```

客户端支持`ping`参数开启心跳检测(默认不开启)，参数值代表心跳间隔秒数。

**注：** gost的代理链仅支持一个HTTP2代理节点，采用就近原则，会将第一个遇到的HTTP2代理节点视为HTTP2代理，其他HTTP2代理节点则被视为HTTPS代理。

#### QUIC
gost对QUIC的支持是基于[quic-go](https://github.com/lucas-clemente/quic-go)库。

服务端:
```bash
gost -L=quic://:6121
```

客户端(Chrome):
```bash
chrome --enable-quic --proxy-server=quic://server_ip:6121
```

**注：** 由于Chrome自身的限制，目前只能通过QUIC访问HTTP网站，无法访问HTTPS网站。

#### KCP
gost对KCP的支持是基于[kcp-go](https://github.com/xtaci/kcp-go)和[kcptun](https://github.com/xtaci/kcptun)库。

服务端:
```bash
gost -L=kcp://:8388
```

客户端:
```bash
gost -L=:8080 -F=kcp://server_ip:8388
```

或者手动指定加密方法和密码(手动指定的加密方法和密码会覆盖配置文件中的相应值)

服务端:
```bash
gost -L=kcp://aes:123456@:8388
```

客户端:
```bash
gost -L=:8080 -F=kcp://aes:123456@server_ip:8388
```

gost会自动加载当前工作目录中的kcp.json(如果存在)配置文件，或者可以手动通过参数指定配置文件路径：
```bash
gost -L=kcp://:8388?c=/path/to/conf/file
```

**注：** 客户端若要开启KCP转发，当且仅当代理链不为空且首个代理节点(第一个-F参数)为kcp类型。

#### 透明代理
基于iptables的透明代理。

```bash
gost -L=redirect://:12345 -F=http2://server_ip:443
```

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

**注：** 如果transport已经支持加密(wss, tls, http2, kcp)，则SOCKS5不会再使用加密方法，防止不必要的双重加密。

#### Shadowsocks
gost对shadowsocks的支持是基于[shadowsocks-go](https://github.com/shadowsocks/shadowsocks-go)库。

服务端(可以通过ota参数开启OTA强制模式，开启后客户端必须使用OTA模式):
```bash
gost -L=ss://aes-128-cfb:123456@:8338?ota=1
```
客户端(可以通过ota参数开启OTA模式):
```bash
gost -L=:8080 -F=ss://aes-128-cfb:123456@server_ip:8338?ota=1
```

##### Shadowsocks UDP relay

目前仅服务端支持UDP，且仅支持OTA模式。

服务端:
```bash
gost -L=ssu://aes-128-cfb:123456@:8338
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



