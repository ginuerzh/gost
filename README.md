gost - GO Simple Tunnel
====

### GO语言实现的安全隧道

#### 特性
1. 支持设置上层代理(客户端，服务器端均可)，支持上层代理认证。
2. 客户端可用作http(s), socks5代理。
3. 服务器端兼容标准的socks5协议, 可直接用作socks5代理, 并额外增加协商加密功能。
4. Tunnel UDP over TCP, UDP数据包使用TCP通道传输，以解决防火墙的限制。
5. 多种加密方式(tls,aes-256-cfb,des-cfb,rc4-md5等)。
6. 客户端兼容shadowsocks协议，可作为shadowsocks服务器。

二进制文件下载：https://bintray.com/ginuerzh/gost/gost/view

Google讨论组: https://groups.google.com/d/forum/go-gost

#### 版本更新
##### v1.7
* 支持认证功能，当作为http(s)代理时使用Basic Auth认证方式，当作为标准socks5代理时使用Username/Password认证方式
###### Bug fix:
* 修正当作为http代理时，POST请求出错问题

##### v1.6
* 增加tls-auth加密方式，此方式必须设置认证密码(-p参数)，原tls加密方式与v1.3版以前兼容
###### Bug fix:
* 修正当不设置上层代理时，连接出错问题

##### v1.5
* 支持设置上层socks5代理(注: http tunnel不支持)
* 支持上层代理认证

##### V1.4
* 支持http tunnel(-http参数)，使用http协议来传输数据(注: 效率低，非特殊情况下，不推荐使用)。

##### v1.3
* tls加密方式增加密码认证功能(与旧版本不兼容)
* 增加版本查看(-v参数)
* -p参数的默认值修改为空

##### v1.2 
* websocket tunnel增加加密功能。

##### v1.1 
* 支持websocket tunnel(-ws参数)，使用websocket协议来传输数据。

#### 参数说明
>  -L=":8080": listen address

>  -P="": proxy for forward

>  -S="": the server that connect to

>  -cert="": tls cert file

>  -key="": tls key file

>  -m="": tunnel cipher method

>  -p="": tunnel cipher password

>  -sm="rc4-md5": shadowsocks cipher method

>  -sp="ginuerzh@gmail.com": shadowsocks cipher password

>  -ss=false: run as shadowsocks server

>  -ws=false: use websocket tunnel

>  -http=false: use http tunnel

>  -v=false: print version


#### 使用方法
##### 基本用法
* 客户端: `gost -L=:8899 -S=server_ip:8080`
* 服务器: `gost -L=:8080`

##### 设置认证信息
* 客户端: `gost -L=admin:123456@:8899 -S=server_ip:8080`
* 服务器: `gost -L=admin:123456@:8080`

注：当服务器端设置了认证，默认的无加密模式(-m为空)不可用，
即客户端或者使用认证方式(标准socks5模式)，或者设置加密方式(gost兼容模式)。

##### 设置加密
* 客户端: `gost -L=:8899 -S=server_ip:8080 -m=rc4-md5 -p=123456`
* 服务器: `gost -L=:8080 -m=rc4-md5 -p=123456`

##### 设置上层代理
* http代理: `gost -L=:8899 -P=http://127.0.0.1:8080`
* http代理(需认证): `gost -L=:8899 -P=http://admin:123456@127.0.0.1:8080`
* socks5代理: `gost -L=:8899 -P=socks://127.0.0.1:1080`
* socks5代理(需认证): `gost -L=:8899 -P=socks://admin:123456@127.0.0.1:1080`

##### 使用websocket tunnel
* 客户端: `gost -L=:8899 -S=server_ip:8080 -ws`
* 服务器: `gost -L=:8080 -ws`

##### 使用http tunnel
* 客户端: `gost -L=:8899 -S=server_ip:8080 -http`
* 服务器: `gost -L=:8080 -http`

注：websocket方式优先级高于http方式，即当-ws与-http参数同时存在时，-http参数无效。

##### 作为shadowsocks服务器
gost支持作为shadowsocks服务器运行(-ss参数)，这样就可以让android手机通过shadowsocks客户端(影梭)使用代理了。

###### 相关参数
> -ss 开启shadowsocks模式

> -sm 设置shadowsocks加密方式(默认为rc4-md5)

> -sp 设置shadowsocks加密密码(默认为ginuerzh@gmail.com)

当无-ss参数时，-sm, -sp参数无效。以上三个参数对服务端无效。

###### 相关命令
* 客户端: `gost -L :8899 -S server_ip:port -sm=rc4-md5 -sp=ginuerzh@gmail.com -ss`
* 服务器: 无需特殊设置，shadowsocks模式只与客户端有关，与服务端无关。

在手机的shadowsocks软件中设置好服务器IP(运行gost客户端电脑的IP)，端口(8899)，加密方法和密码就可以使用了。

注：shadowsocks模式与正常模式是不兼容的，当作为shadowsocks模式使用时(有-ss参数)，浏览器不能使用。


#### tunnel加密说明
##### 目前支持的加密方法
tls, tls-auth, aes-128-cfb, aes-192-cfb, aes-256-cfb, des-cfb, bf-cfb, cast5-cfb, rc4-md5, rc4, table

##### Client

Client端通过-m参数设置加密方式，默认为不加密(-m参数为空)。

如果设置的加密方式不被支持，则默认为不加密。

当设置的加密方式为tls时，-p参数无效。

当设置的加密方式为非tls时，通过-p参数设置加密密码，且不能为空；-p参数必须与Server端的-p参数相同。

##### Server

Server端通过-m参数设置加密方式，默认为不加密(-m参数为空)。

如果设置的加密方式不被支持，默认为不处理。

如果没有设置加密方式(-m参数为空)，则由client端控制加密方式，即client端可通过-m参数指定Server端使用哪种加密方式。

如果设置了加密方式(-m参数不为空)，client端必须使用与Server端相同的加密方式。

当设置的加密方式为tls，tls-auth时，-key参数可手动指定公钥文件，-cert参数可手动指定私钥文件，如果未指定，则使用默认的公钥与私钥。

当设置的加密方式为tls时，-p参数无效；为tls-auth时，通过-p参数设置认证密码，且不能为空。

当设置的加密方式为非tls，tls-auth时，-key，-cert参数无效；通过-p参数设置加密密码，且不能为空。


