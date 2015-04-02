gost - GO Simple Tunnel
====

###GO语言实现的安全隧道

####特性
1. 客户端可同时用作http(s), socks5代理。
2. 服务器端使用标准的socks5协议，可直接作为socks5代理。
3. 多种加密方式(tls, aes-256-cfb, des-cfb， rc4-md5等)。
4. 客户端兼容shadowsocks协议，可作为shadowsocks服务器。
5. 支持设置上层http代理。

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
`$ gost -L=your_server_ip:443`

#####客户端:
`$ gost -L=:8080 -S=your_server_ip:443`
