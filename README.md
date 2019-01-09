gost - GO Simple Tunnel
======

### GO语言实现的安全隧道

[![GoDoc](https://godoc.org/github.com/ginuerzh/gost?status.svg)](https://godoc.org/github.com/ginuerzh/gost)
[![Build Status](https://travis-ci.org/ginuerzh/gost.svg?branch=master)](https://travis-ci.org/ginuerzh/gost)
[![Go Report Card](https://goreportcard.com/badge/github.com/ginuerzh/gost)](https://goreportcard.com/report/github.com/ginuerzh/gost)
[![codecov](https://codecov.io/gh/ginuerzh/gost/branch/master/graphs/badge.svg)](https://codecov.io/gh/ginuerzh/gost/branch/master)
[![GitHub release](https://img.shields.io/github/release/ginuerzh/gost.svg)](https://github.com/ginuerzh/gost/releases/latest)
[![Snap Status](https://build.snapcraft.io/badge/ginuerzh/gost.svg)](https://build.snapcraft.io/user/ginuerzh/gost)
[![Docker Build Status](https://img.shields.io/docker/build/ginuerzh/gost.svg)](https://hub.docker.com/r/ginuerzh/gost/)
 
[English README](README_en.md)

特性
------

* 多端口监听
* 可设置转发代理，支持多级转发(代理链)
* 支持标准HTTP/HTTPS/HTTP2/SOCKS4(A)/SOCKS5代理协议
* Web代理支持[探测防御](https://docs.ginuerzh.xyz/gost/probe_resist/)
* [支持多种隧道类型](https://docs.ginuerzh.xyz/gost/configuration/)
* [SOCKS5代理支持TLS协商加密](https://docs.ginuerzh.xyz/gost/socks/)
* [Tunnel UDP over TCP](https://docs.ginuerzh.xyz/gost/socks/)
* [TCP透明代理](https://docs.ginuerzh.xyz/gost/redirect/)
* [本地/远程TCP/UDP端口转发](https://docs.ginuerzh.xyz/gost/port-forwarding/)
* [支持Shadowsocks(TCP/UDP)协议](https://docs.ginuerzh.xyz/gost/ss/)
* [支持SNI代理](https://docs.ginuerzh.xyz/gost/sni/)
* [权限控制](https://docs.ginuerzh.xyz/gost/permission/)
* [负载均衡](https://docs.ginuerzh.xyz/gost/load-balancing/)
* [路由控制](https://docs.ginuerzh.xyz/gost/bypass/)
* [DNS控制](https://docs.ginuerzh.xyz/gost/dns/)

Wiki站点: <https://docs.ginuerzh.xyz/gost/>

Google讨论组: <https://groups.google.com/d/forum/go-gost>

Telegram讨论群: <https://t.me/gogost>

安装
------

#### 二进制文件

<https://github.com/ginuerzh/gost/releases>

#### 源码编译

```bash
go get -u github.com/ginuerzh/gost/cmd/gost
```

#### Docker

```bash
docker pull ginuerzh/gost
```

#### Ubuntu商店

```bash
sudo snap install gost
```

快速上手
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

* 多端口监听

```bash
gost -L=http2://:443 -L=socks5://:1080 -L=ss://aes-128-cfb:123456@:8338
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
gost -L=:8080 -F=quic://192.168.1.1:6121 -F=socks5+wss://192.168.1.2:1080 -F=http2://192.168.1.3:443 ... -F=a.b.c.d:NNNN
```

gost按照-F设置的顺序通过代理链将请求最终转发给a.b.c.d:NNNN处理，每一个转发代理可以是任意HTTP/HTTPS/HTTP2/SOCKS4/SOCKS5/Shadowsocks类型代理。

#### 本地端口转发(TCP)

```bash
gost -L=tcp://:2222/192.168.1.1:22 [-F=...]
```

将本地TCP端口2222上的数据(通过代理链)转发到192.168.1.1:22上。当代理链末端(最后一个-F参数)为SSH转发通道类型时，gost会直接使用SSH的本地端口转发功能:

```bash
gost -L=tcp://:2222/192.168.1.1:22 -F forward+ssh://:2222
```

#### 本地端口转发(UDP)

```bash
gost -L=udp://:5353/192.168.1.1:53?ttl=60 [-F=...]
```

将本地UDP端口5353上的数据(通过代理链)转发到192.168.1.1:53上。
每条转发通道都有超时时间，当超过此时间，且在此时间段内无任何数据交互，则此通道将关闭。可以通过`ttl`参数来设置超时时间，默认值为60秒。

**注:** 转发UDP数据时，如果有代理链，则代理链的末端(最后一个-F参数)必须是gost SOCKS5类型代理，gost会使用UDP over TCP方式进行转发。

#### 远程端口转发(TCP)

```bash
gost -L=rtcp://:2222/192.168.1.1:22 [-F=... -F=socks5://172.24.10.1:1080]
```
将172.24.10.1:2222上的数据(通过代理链)转发到192.168.1.1:22上。当代理链末端(最后一个-F参数)为SSH转发通道类型时，gost会直接使用SSH的远程端口转发功能:

```bash
gost -L=rtcp://:2222/192.168.1.1:22 -F forward+ssh://:2222
```

#### 远程端口转发(UDP)

```bash
gost -L=rudp://:5353/192.168.1.1:53?ttl=60 [-F=... -F=socks5://172.24.10.1:1080]
```
将172.24.10.1:5353上的数据(通过代理链)转发到192.168.1.1:53上。
每条转发通道都有超时时间，当超过此时间，且在此时间段内无任何数据交互，则此通道将关闭。可以通过`ttl`参数来设置超时时间，默认值为60秒。

**注:** 转发UDP数据时，如果有代理链，则代理链的末端(最后一个-F参数)必须是GOST SOCKS5类型代理，gost会使用UDP-over-TCP方式进行转发。

#### HTTP2

gost的HTTP2支持两种模式：
* 作为标准的HTTP2代理，并向下兼容HTTPS代理。
* 作为通道传输其他协议。

##### 代理模式
服务端:
```bash
gost -L=http2://:443
```
客户端:
```bash
gost -L=:8080 -F=http2://server_ip:443
```

##### 通道模式
服务端:
```bash
gost -L=h2://:443
```
客户端:
```bash
gost -L=:8080 -F=h2://server_ip:443
```

#### QUIC
gost对QUIC的支持是基于[quic-go](https://github.com/lucas-clemente/quic-go)库。

服务端:
```bash
gost -L=quic://:6121
```

客户端:
```bash
gost -L=:8080 -F=quic://server_ip:6121
```

**注：** QUIC模式只能作为代理链的第一个节点。

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

gost会自动加载当前工作目录中的kcp.json(如果存在)配置文件，或者可以手动通过参数指定配置文件路径：
```bash
gost -L=kcp://:8388?c=/path/to/conf/file
```

**注：** KCP模式只能作为代理链的第一个节点。

#### SSH

gost的SSH支持两种模式：
* 作为转发通道，配合本地/远程TCP端口转发使用。
* 作为通道传输其他协议。

##### 转发模式
服务端:
```bash
gost -L=forward+ssh://:2222
```
客户端:
```bash
gost -L=rtcp://:1222/:22 -F=forward+ssh://server_ip:2222
```

##### 通道模式
服务端:
```bash
gost -L=ssh://:2222
```
客户端:
```bash
gost -L=:8080 -F=ssh://server_ip:2222?ping=60
```

可以通过`ping`参数设置心跳包发送周期，单位为秒。默认不发送心跳包。


#### 透明代理
基于iptables的透明代理。

```bash
gost -L=redirect://:12345 -F=http2://server_ip:443
```

#### obfs4
此功能由[@isofew](https://github.com/isofew)贡献。

服务端:
```bash
gost -L=obfs4://:443
```

当服务端运行后会在控制台打印出连接地址供客户端使用:
```
obfs4://:443/?cert=4UbQjIfjJEQHPOs8vs5sagrSXx1gfrDCGdVh2hpIPSKH0nklv1e4f29r7jb91VIrq4q5Jw&iat-mode=0
```

客户端:
```
gost -L=:8888 -F='obfs4://server_ip:443?cert=4UbQjIfjJEQHPOs8vs5sagrSXx1gfrDCGdVh2hpIPSKH0nklv1e4f29r7jb91VIrq4q5Jw&iat-mode=0'
```

加密机制
------

#### HTTP

对于HTTP可以使用TLS加密整个通讯过程，即HTTPS代理：

服务端:

```bash
gost -L=https://:443
```
客户端:

```bash
gost -L=:8080 -F=http+tls://server_ip:443
```

#### HTTP2

gost的HTTP2代理模式仅支持使用TLS加密的HTTP2协议，不支持明文HTTP2传输。

gost的HTTP2通道模式支持加密(h2)和明文(h2c)两种模式。

#### SOCKS5

gost支持标准SOCKS5协议的no-auth(0x00)和user/pass(0x02)方法，并在此基础上扩展了两个：tls(0x80)和tls-auth(0x82)，用于数据加密。

服务端:

```bash
gost -L=socks5://:1080
```

客户端:

```bash
gost -L=:8080 -F=socks5://server_ip:1080
```

如果两端都是gost(如上)则数据传输会被加密(协商使用tls或tls-auth方法)，否则使用标准SOCKS5进行通讯(no-auth或user/pass方法)。

#### Shadowsocks
gost对shadowsocks的支持是基于[shadowsocks-go](https://github.com/shadowsocks/shadowsocks-go)库。

服务端:

```bash
gost -L=ss://chacha20:123456@:8338
```
客户端:

```bash
gost -L=:8080 -F=ss://chacha20:123456@server_ip:8338
```

##### Shadowsocks UDP relay

目前仅服务端支持UDP Relay。

服务端:

```bash
gost -L=ssu://chacha20:123456@:8338
```

#### TLS
gost内置了TLS证书，如果需要使用其他TLS证书，有两种方法：
* 在gost运行目录放置cert.pem(公钥)和key.pem(私钥)两个文件即可，gost会自动加载运行目录下的cert.pem和key.pem文件。
* 使用参数指定证书文件路径：
```bash
gost -L="http2://:443?cert=/path/to/my/cert/file&key=/path/to/my/key/file"
```

对于客户端可以通过`secure`参数开启服务器证书和域名校验:
```bash
gost -L=:8080 -F="http2://server_domain_name:443?secure=true"
```

对于客户端可以指定CA证书进行[证书锁定](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning)(Certificate Pinning):
```bash
gost -L=:8080 -F="http2://:443?ca=ca.pem"
```
证书锁定功能由[@sheerun](https://github.com/sheerun)贡献
