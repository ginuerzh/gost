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

####版本更新
#####v1.1 
*	支持websocket tunnel。

二进制文件下载：https://bintray.com/ginuerzh/gost/gost/v1.1/view

#####v1.2 
*	websocket tunnel增加加密功能。

二进制文件下载：https://bintray.com/ginuerzh/gost/gost/v1.2/view

####参数说明
>  -L=":8080": listen address

>  -P="": proxy for forward

>  -S="": the server that connecting to

>  -cert="": cert file for tls

>  -key="": key file for tls

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


####tunnel加密说明
#####目前支持的加密方法
tls, aes-128-cfb, aes-192-cfb, aes-256-cfb, des-cfb, bf-cfb, cast5-cfb, rc4-md5, rc4, table

#####Client

Client端通过-m参数设置加密方式，默认为不加密(-m参数为空)。

如果设置的加密方式不被支持，则默认为不加密。

当设置的加密方式为tls时，-p参数无效。

当设置的加密方式为非tls时，通过-p参数设置加密密码，且不能为空，默认密码为ginuerzh@gmail.com；-p参数必须与Server端的-p参数相同。

#####Server

Server端通过-m参数设置加密方式，默认为不加密(-m参数为空)。

如果设置的加密方式不被支持，默认为不处理。

如果没有设置加密方式(-m参数为空)，则由client端控制加密方式，即client端可通过-m参数指定Server端使用哪种加密方式。

如果设置了加密方式(-m参数不为空)，client端必须使用与Server端相同的加密方式。

当设置的加密方式为tls时，-p参数无效；-key参数可手动指定公钥文件，-cert参数可手动指定私钥文件，如果未指定，则使用默认的公钥与私钥。

当设置的加密方式为非tls时，-key，-cert参数无效；通过-p参数设置加密密码，且不能为空，默认密码为ginuerzh@gmail.com。
