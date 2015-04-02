gost - GO Simple Tunnel
====

###GO语言实现的安全隧道

####目的
目前这种软件已经很多了，像shadowsocks, goagent等等都很成熟了，那为什么我要再发明一个轮子？
一般公司的上网都是通过公司代理服务器，而且大部分都会有或多或少的限制，比如只能访问特定的端口(80, 443, 8080),
只允许http协议等。
我一开始在网上找了好多类似功能的软件，但都有一个问题：无法设置上层代理，这样就无法通过公司网络。
最后找了半天也没找到，于是就自己写了一个，主要是在公司使用。

增加shadowsocks服务器模式，是方便我的手机使用，这样我的手机就可以使用shadowsocks客户端连接到本地的shadowsocks服务器，几乎所有软件都可以使用了。

#####注：前提条件是要有一台可访问的具有公网IP的主机。


####特性
1. 支持设置上层http代理。
2. 客户端可用作http(s), socks5代理。
3. 服务器端兼容标准的socks5协议, 可直接用作socks5代理, 并额外增加协商加密功能。
4. Tunnel UDP over TCP, UDP数据包使用TCP通道传输，以解决防火墙的限制。
5. 多种加密方式(tls,aes-256-cfb,des-cfb,rc4-md5等)。
6. 客户端兼容shadowsocks协议，可作为shadowsocks服务器。

####参数说明
>  -L=":8080": listen address

>  -P="": proxy for forward

>  -S="": the server that connecting to

>  -cert="cert.pem": cert.pem file for tls

>  -key="key.pem": key.pem file for tls

>  -m="tls": tunnel cipher method

>  -p="ginuerzh@gmail.com": tunnel cipher password

>  -sm="rc4-md5": shadowsocks cipher method

>  -sp="ginuerzh@gmail.com": shadowsocks cipher password

>  -ss=false: run as shadowsocks server


####使用方法
#####服务器端:
`$ gost -L=:443`

#####服务器端有上层http代理:
`$ gost -L=:443 -P=proxy_ip:port`

#####客户端(默认使用tls加密方法):
`$ gost -L=:8080 -S=your_server_ip:443`

#####客户端有上层http代理:
`$ gost -L=:8080 -S=your_server_ip:443 -P=proxy_ip:port`

#####作为shadowsocks服务器(默认使用rc4-md5加密，密码:ginuerzh@gmail.com):
`$ gost -L=:8080 -S=your_server_ip:443 -ss`
