gost - GO Simple Tunnel
====

### GO语言实现的安全隧道

#### 特性
1. 可同时监听多端口。
2. 可设置多转发代理。
3. 兼容标准http/socks5代理协议。
4. socks5代理支持tls协商加密。
4. Tunnel UDP over TCP。
6. 兼容shadowsocks协议。

二进制文件下载：https://github.com/ginuerzh/gost/releases

Google讨论组: https://groups.google.com/d/forum/go-gost

在gost中，gost与其他代理服务都被看作是代理节点(proxy node)，gost可以自己处理请求，或者将请求转发给任意一个或多个代理节点。

#### 参数说明

-L和-F参数格式：[scheme://][user:pass@host]:port

scheme分为两部分: protocol - 代理协议类型(http, socks5, shadowsocks), transport - 数据传输方式(tcp, websocket, tls)。

> http - 作为标准http代理: http://:8080

> http+tls - 作为http代理，使用tls传输数据: http+tls://:8080

> socks - 作为标准socks5代理: socks://:8080

> socks+ws -作为socks5代理，使用websocket传输数据: socks+ws://:8080

> tls - 作为http/socks5代理，使用tls传输数据: tls://:8080

> ss - 作为shadowsocks服务，ss://aes-256-cfb:123456@:8080

#### 使用方法

##### 不设置转发代理

<img src="https://ginuerzh.github.io/images/gost_01.png" />
* 作为标准http/socks5代理
```bash
gost -L=:8080
```

* 设置代理认证信息
```bash
gost -L=admin:123456@localhost:8080
```

* 多端口监听
```bash
gost -L=http://localhost:8080 -L=socks://localhost:8081 -L=ss://aes-256-cfb:123456@:8082
```

##### 设置转发代理

<img src="https://ginuerzh.github.io/images/gost_02.png" />
```bash
gost -L=:8080 -F=192.168.1.1:8081
```

* 转发代理认证
```bash
gost -L=:8080 -F=http://admin:123456@192.168.1.1:8081
```

##### 设置多个转发代理(转发链)

<img src="https://ginuerzh.github.io/images/gost_03.png" />
```bash
gost -L=:8080 -F=http+tls://192.168.1.1:8081 -F socks+ws://192.168.1.2:8082 -F=··· -F=a.b.c.d:NNNN
```
gost通过转发链按照-F设置顺序将请求最终转发给a.b.c.d:NNNN处理，每一个转发代理可以是任意一种类型的代理(http/socks5)



