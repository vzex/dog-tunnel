# dtunnel_lite

## 介绍
lite版本，非p2p版本的狗洞，没有打洞功能，单纯的c/s结构，提供高效的端口映射和socks5服务，可转发tcp或者udp端口，支持透明路由模式
基于kcp的网络传输协议

## 安装
安装依赖

go get github.com/klauspost/reedsolomon

go get github.com/cznic/zappy

编译主程序

go get -u -d github.com/vzex/dog-tunnel && cd $GOPATH/src/github.com/vzex/dog-tunnel/ && git checkout udpVersion && make

(windows用户请自行调整目录)
## 用法
请参考HowToUse.txt

## License

[MIT License](LICENSE)

## Credits
![欢迎使用支付宝对该项目进行捐赠](https://raw.githubusercontent.com/vzex/dog-tunnel/udpVersion/dog-tunnel.png)

author: vzex@163.com
