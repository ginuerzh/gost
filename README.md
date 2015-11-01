gost - GO Simple Tunnel
====

### GO语言实现的安全隧道

#### 特性
* 可同时监听多端口
* 可设置转发代理，支持多级转发(转发链)
* 兼容标准http/socks5代理协议
* socks5代理支持tls协商加密
* Tunnel UDP over TCP
* 兼容shadowsocks协议

二进制文件下载：https://github.com/ginuerzh/gost/releases

Google讨论组: https://groups.google.com/d/forum/go-gost

在gost中，gost与其他代理服务都被看作是代理节点，gost可以自己处理请求，或者将请求转发给任意一个或多个代理节点。

#### 参数说明

##### -L和-F参数格式
```bash
[scheme://][user:pass@host]:port
```
scheme分为两部分: protocol+transport

protocol: 代理协议类型(http, socks5, shadowsocks), transport: 数据传输方式(tcp, websocket, tls), 二者可以任意组合，或单独使用。

> http - 作为标准http代理: http://:8080

> http+tls - 作为http代理，使用tls传输数据: http+tls://:8080

> socks - 作为标准socks5代理: socks://:8080

> socks+ws - 作为socks5代理，使用websocket传输数据: socks+ws://:8080

> tls - 作为http/socks5代理，使用tls传输数据: tls://:8080

> ss - 作为shadowsocks服务，ss://aes-256-cfb:123456@:8080

##### 开启日志

> -logtostderr : 输出到控制台

> -v=4 : 日志级别(1-4)，级别越高，日志越详细

> -log_dir=. : 输出到目录


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
gost -L=:8080 -L=ss://aes-256-cfb:123456@:8081
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

##### 设置多级转发代理(转发链)

<img src="https://ginuerzh.github.io/images/gost_03.png" />
```bash
gost -L=:8080 -F=http://192.168.1.1:8081 -F=socks://192.168.1.2:8082 -F=a.b.c.d:NNNN
```
gost按照-F设置顺序通过转发链将请求最终转发给a.b.c.d:NNNN处理，每一个转发代理可以是任意http/socks5类型代理。

##### 加密机制

对于http或socks5都可以使用tls加密整个通讯过程：

http:
```bash
gost -L=http+tls://:8080
```

socks5:
```bash
gost -L=socks+tls://:8080
```

gost针对socks5额外提供了协商的tls传输方法，与上面的不同之处在于socks5最开始的方法选择(method selection)过程是非加密的。
如果连接方是gost则后续的通讯使用tls加密，否则使用标准socks5进行通讯(未加密)。

gost内置了tls证书，如果需要使用其他的tls证书，在gost目录放置key.pem(公钥)和cert.pem(私钥)两个文件即可。

#### SOCKS5 UDP数据处理

##### 不设置转发代理

<img src="https://ginuerzh.github.io/images/udp01.png" height=100 />

gost作为标准socks5代理处理UDP数据

##### 设置转发代理

<img src="https://ginuerzh.github.io/images/udp02.png" height=100 />

##### 设置多个转发代理(转发链)

<img src="https://ginuerzh.github.io/images/udp03.png" height=200 />

当设置转发代理时，gost会使用UDP-Over-TCP方式转发UDP数据。proxy1 - proxyN可以为任意http/socks5类型代理。

##### 限制条件

转发链中的http代理必须支持CONNECT方法。

如果要转发socks5的BIND和UDP请求，转发链的末端(最后一个-F参数)必须是gost socks5类型代理。



