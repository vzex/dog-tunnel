# Dog Tunnel(狗洞)
[README in English](https://github.com/f06ybeast/dog-tunnel/blob/master/README.en.md) 
## Introduction

基于kcp的p2p端口映射工具，同时支持socks5代理

## 编译
安装依赖

go get github.com/go-sql-driver/mysql

go get github.com/klauspost/reedsolomon

go get github.com/cznic/zappy

编译程序
go get -u -d github.com/vzex/dog-tunnel && cd $GOPATH/src/github.com/vzex/dog-tunnel/ && git checkout master && make

(windows用户自行修改路径)

## 服务器搭建

编译出来的程序有两个dtunnel_s, dtunnel

dtunnel_s 为服务端 dtunnel 为客户端

dtunnel 的用法参考官网 http://dog-tunnel.tk(注:官网因为挂在一个不靠谱的vps上到期就停止续费了，所以不再提供官方的p2p服务器了，之后的二进制版本会发布在github中)

dtunnel_s 启动时会监听一个tcp端口，通过-addr设置，如果需要-ssl(默认是false)，那么要指定-cert加载ssl证书，之后客户端连接也要打开-ssl开关(默认是true的)
-addrudp 是p2p打洞的辅助udp端口，能提高打洞成功率,对应dtunnel参数-buster指定同样的ip和端口

dtunnel_s 支持远程接口管理，如果需要，可通过-admin 指定ip:端口，比如-admin 127.0.0.1:1234

支持的命令列表
```
http://127.0.0.1:1234/admin?cmd=servers 列出所有reg的用户
http://127.0.0.1:1234/admin?cmd=sessions&server=a 列出所有link到a的会话
http://127.0.0.1:1234/admin?admin?cmd=kicksession&server=a&session=1 踢掉会话号为1的客户端(link端)
http://127.0.0.1:1234/admin?cmd=kickserver&server=a 踢掉reg a的客户端
http://127.0.0.1:1234/admin?cmd=broadcast&type=s&msg=test&quit=true 广播消息,type(s:reg端,c:link端,a:所有客户端),msg消息内容,quit(缺省参数，非空则广播后客户端被踢掉)

http://127.0.0.1:1234/admin?cmd=usersetting (用户管理相关api，需要连接mysql)
配置mysql需要用到auth/auth.sql 建表语句，建表前请先创建数据库dogtunnel
连接mysql需要在启动参数中添加 -dbhost -dbuser -dbpass 参数，加了mysql之后就必须通过-key才能登录服务器
mysql的使用方法请自行学习
usersetting下面有多个子命令(直接拼在上面主api后面)
&action=list&limita=0&limitb=10,分页列出用户信息
&action=limit&user=aaa&size=10000 限制用户aaa的c/s模式流量上线为10k（每日）
&action=add&user=aaa&passwd=1111&type=admin 添加用户aaa，密码1111，类型type(admin管理员(最高权限),black黑名单,super高级用户,type不传默认普通用户),返回的key用户dtunnel 的-key参数
&action=get&user=aaa 返回aaa的用户信息
&action=del&user=aaa 删除aaa
&action=key&user=aaa 返回aaa的新key
&action=set&user=aaa&type=super&serven=10&sessionn=100&pipen=10&sameip=10,对aaa的账号做功能限制，type指定的类型有默认的几套配置，也可以通过指定servern(可以注册的名字数上限),sessionn(每个注册的服务器可以连接的会话数上限),pipen(每个会话最多支持几条p2p管道),sameip(同ip可注册服务数上限)来单独指定配置

```
## Thanks

[netroby](https://github.com/netroby)

## License

[MIT License](LICENSE)

## Credits
![Welcome donate with Alipay && 欢迎使用支付宝对该项目进行捐赠](https://raw.githubusercontent.com/vzex/dog-tunnel/udpVersion/dog-tunnel.png)

author: vzex@163.com
