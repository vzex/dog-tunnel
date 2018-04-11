# Dog Tunnel
## Introduction

kcp-based p2p port mapping tool that supports SOCKS5 proxy

## Compiling
Installation dependencies

go get github.com/go-sql-driver/mysql

go get github.com/klauspost/reedsolomon

go get github.com/cznic/zappy

Compiler
go get -u -d github.com/vzex/dog-tunnel && cd $GOPATH/src/github.com/vzex/dog-tunnel/ && git checkout master && make

(Windows users modify the path by themselves)

## server setup

The compiled program has two dtunnel_s, dtunnel

dtunnel_s is the server dtunnel is the client

The use of dtunnel reference official website http://dog-tunnel.tk (Note: The official website because it hangs on a vps unreliable expires to stop the renewals, so no longer provide the official p2p server, after the binary version will Posted in github

When dtunnel_s starts, it will listen to a TCP port and set it with -addr. If you need -ssl (default is false), then you must specify -cert to load the ssl certificate. Then the client connection must also open the -ssl switch (default is true).
-addrudp is the auxiliary udp port for p2p hole punching. It can increase the success rate of hole punching. The corresponding dtunnel parameter -buster specifies the same ip and port.

dtunnel_s supports remote interface management. If necessary, specify ip:port with -admin, for example -admin 127.0.0.1:1234

List of supported commands
```
http://127.0.0.1:1234/admin?cmd=servers List all reg users
http://127.0.0.1:1234/admin?cmd=sessions&server=a list all links to a session
http://127.0.0.1:1234/admin?admin?cmd=kicksession&server=a&session=1 Kick off the client with session number 1 (link end)
http://127.0.0.1:1234/admin?cmd=kickserver&server=a Kick off reg a client
http://127.0.0.1:1234/admin?cmd=broadcast&type=s&msg=test&quit=true broadcast message, type(s:reg, c:link, a: all clients), msg message content, quit Provincial parameters, non-empty broadcast after the client is kicked out)

http://127.0.0.1:1234/admin?cmd=usersetting (user management related api, need to connect mysql)
Configure mysql need to use auth/auth.sql table statement, create the database dogtunnel before the construction of the table
Connection mysql need to add -dbhost -dbuser -dbpass parameters in the startup parameters, after adding mysql must pass -key to log in to the server
The use of mysql please learn on your own
There are multiple subcommands under usersetting (directly spelled above main api)
&action=list&limita=0&limitb=10, pagination lists user information
&action=limit&user=aaa&size=10000 Limit user aaa's c/s mode traffic to 10k (daily)
&action=add&user=aaa&passwd=1111&type=admin Add user aaa, password 1111, type type (admin administrator (highest privilege), black blacklist, super advanced user, type not pass default normal user), return key user dtunnel - Key parameter
&action=get&user=aaa Returns aaa's user information
&action=del&user=aaa delete aaa
&action=key&user=aaa Returns aaa's new key
&action=set&user=aaa&type=super&serven=10&sessionn=100&pipen=10&sameip=10, which restricts the function of aaa account. The type specified by the type has a default set of configurations, and can also specify servern (the maximum number of registered names), sessionn (The upper limit of the number of sessions that each registered server can connect to), pipen (up to several p2p pipes per session), and single ip (configured to the same number of ip configurable services)

```
## Thanks

[netroby] (https://github.com/netroby)

## License

[MIT License](LICENSE)

## Credits
![Welcome donate with Alipay && Welcome to Alipay for this project] (https://raw.githubusercontent.com/vzex/dog-tunnel/udpVersion/dog-tunnel.png)

Author: vzex@163.com