gost - GO Simple Tunnel
====

###GO语言实现的安全隧道

####特性
1. 支持标准socks5协议(rfc1928)。
2. 多种加密方式(tls, 以及aes-256-cfb, des-cfb， rc4-md5等shadowsocks兼容的加密方式)。
3. 客户端兼容shadowsocks协议。
4. 支持设置上层http代理

####参数说明
>  -L=":8080": listen address

>  -P="": proxy for forward

>  -S="": the server that connecting to

>  -cert="cert.pem": cert.pem file for tls

>  -key="key.pem": key.pem file for tls

>  -m="tls": cipher method

>  -p="ginuerzh@gmail.com": cipher password

>  -sm="rc4-md5": shadowsocks cipher method

>  -sp="ginuerzh@gmail.com": shadowsocks cipher password

>  -ss=false: shadowsocks compatible


####使用方法
#####服务器端:
`$ gost -L=your_server_ip:443`

#####客户端:
`$ gost -L=:8080 -S=your_server_ip:443`
