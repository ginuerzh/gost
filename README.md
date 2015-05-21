gost - GO Simple Tunnel
====

###GO语言实现的安全隧道

####特性
1. 支持设置上层http代理。
2. 客户端可用作http(s), socks5代理。
3. 服务器端兼容标准的socks5协议, 可直接用作socks5代理, 并额外增加协商加密功能。
4. Tunnel UDP over TCP, UDP数据包使用TCP通道传输，以解决防火墙的限制。
5. 多种加密方式(tls,aes-256-cfb,des-cfb,rc4-md5等)。
6. 客户端兼容shadowsocks协议，可作为shadowsocks服务器。

二进制文件下载：https://bintray.com/ginuerzh/gost/gost/v1.3/view

Google讨论组: https://groups.google.com/forum/#!forum/go-gost

####版本更新
#####v1.3
*	tls加密方式增加密码认证功能(与旧版本不兼容)
*	增加版本查看(-v参数)
*	-p参数的默认值修改为空

#####v1.2 
*	websocket tunnel增加加密功能。

#####v1.1 
*	支持websocket tunnel。

####参数说明
>  -L=":8080": listen address

>  -P="": proxy for forward

>  -S="": the server that connect to

>  -cert="": cert file for tls

>  -key="": key file for tls

>  -m="": tunnel cipher method

>  -p="": tunnel cipher password

>  -sm="rc4-md5": shadowsocks cipher method

>  -sp="ginuerzh@gmail.com": shadowsocks cipher password

>  -ss=false: run as shadowsocks server

>  -ws=false: use websocket for tunnel

>  -v=false: print version


####使用方法
#####服务器端:
`gost -L=:8080`

#####服务器端设置加密:
`gost -L=:8080 -m=aes-256-cfb -p=123456`

#####服务器端有上层http代理:
`gost -L=:8080 -m=aes-256-cfb -p=123456 -P=proxy_ip:port`

#####客户端:
`gost -L=:8899 -S=your_server_ip:8080`

#####客户端设置加密:
`gost -L=:8899 -S=your_server_ip:8080 -m=aes-256-cfb -p=123456`

#####客户端有上层http代理:
`gost -L=:8899 -S=your_server_ip:8080 -m=aes-256-cfb -p=123456 -P=proxy_ip:port`

#####使用websocket tunnel
* 服务器端
`gost -L=:8080 -m=aes-256-cfb -p=123456 -ws`
* 客户端
`gost -L=:8899 -S=your_server_ip:8080 -m=aes-256-cfb -p=123456 -ws`

#####作为shadowsocks服务器:
gost支持作为shadowsocks服务器运行(-ss参数)，这样就可以让android手机通过shadowsocks客户端(影梭)使用代理了。

######相关参数：
>	-ss 	开启shadowsocks模式

>	-sm 	设置shadowsocks加密方式(默认为rc4-md5)

>	-sp    	设置shadowsocks加密密码(默认为ginuerzh@gmail.com)

当无-ss参数时，-sm, -sp参数无效。以上三个参数对服务端无效。

######相关命令：
* 服务端：无需特殊设置，shadowsocks模式只与客户端有关，与服务端无关。
* 客户端：`gost -L :8899 -S demo-project-gostwebsocket.c9.io -sm=rc4-md5 -sp=ginuerzh@gmail.com -ss`

在手机的shadowsocks软件中设置好服务器(运行gost电脑的IP)，端口(8899)，加密方法和密码就可以使用了。

注：shadowsocks模式与正常模式是不兼容的，当作为shadowsocks模式使用时(有-ss参数)，浏览器不能使用。


####tunnel加密说明
#####目前支持的加密方法
tls, aes-128-cfb, aes-192-cfb, aes-256-cfb, des-cfb, bf-cfb, cast5-cfb, rc4-md5, rc4, table

#####Client

Client端通过-m参数设置加密方式，默认为不加密(-m参数为空)。

如果设置的加密方式不被支持，则默认为不加密。

当设置的加密方式为tls时，可通过-p参数设置验证密码(若服务端支持密码验证功能)。

当设置的加密方式为非tls时，通过-p参数设置加密密码，且不能为空；-p参数必须与Server端的-p参数相同。

#####Server

Server端通过-m参数设置加密方式，默认为不加密(-m参数为空)。

如果设置的加密方式不被支持，默认为不处理。

如果没有设置加密方式(-m参数为空)，则由client端控制加密方式，即client端可通过-m参数指定Server端使用哪种加密方式。

如果设置了加密方式(-m参数不为空)，client端必须使用与Server端相同的加密方式。

当设置的加密方式为tls时，-key参数可手动指定公钥文件，-cert参数可手动指定私钥文件，如果未指定，则使用默认的公钥与私钥。
可通过-p参数设定验证密码(可选),若设置，则客户端必须通过-p参数设置相同的密码。

当设置的加密方式为非tls时，-key，-cert参数无效；通过-p参数设置加密密码，且不能为空。
