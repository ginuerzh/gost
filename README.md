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
7. v1.1支持websocket。

二进制文件下载：https://bintray.com/ginuerzh/gost/gost

####参数说明
>  -L=":8080": listen address

>  -P="": proxy for forward

>  -S="": the server that connecting to

>  -cert="": cert.pem file for tls

>  -key="": key.pem file for tls

>  -m="": tunnel cipher method

>  -p="ginuerzh@gmail.com": tunnel cipher password

>  -sm="rc4-md5": shadowsocks cipher method

>  -sp="ginuerzh@gmail.com": shadowsocks cipher password

>  -ss=false: run as shadowsocks server

>  -ws=false: use websocket for tunnel


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
