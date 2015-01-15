# Dog Tunnel

## Introduction
This tunnel is a lite version if dog-tunnel, and actions without a middle server, has no ability of udp traversal, but simple and faster
### Example
first, start a server
server: ./dtunnel_lite -v -service 127.0.0.1:1234 -dnscache 10

then start a client, you can seed the example below:
socks5 example:
client: ./dtunnel_lite -v -service 127.0.0.1:1234 -local :8787

ssh port forward example:
client: ./dtunnel_lite -v -service 127.0.0.1:1234 -local :8787 -action :22

It's better to add the -encrypt arg for privacy in client
you can add "-auth" on both sides for authorize

The default mode is udp mode, and is faster in the poor network than tcp mode, you can also use tcp mode with "-tcp" on both sides.
## License

[MIT License](LICENSE)

## Credits
![欢迎使用支付宝对该项目进行捐赠](https://raw.githubusercontent.com/vzex/dog-tunnel/udpVersion/dog-tunnel.png)

author: vzex@163.com
