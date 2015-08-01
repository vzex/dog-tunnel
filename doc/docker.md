# Run dog tunnel with docker container

First things, you need make sure you have installed docker on your linux environment.
Following instruction was testing under ubuntu 15.04 or above.

On server side, your systemd boot file like this , named with dt.service location at 
/etc/systemd/system/dt.service


```
[Unit]
Description=dt
After=network.target
Requires=network.target

[Service]
TimeoutStartSec=0
ExecStart=/usr/bin/docker run --rm --name dt -p 123:123/udp netroby/alpine-dog-tunnel /usr/bin/dtunnel_lite -service 0.0.0.0:123 -auth verystrongpassword2
Restart=always

[Install]
WantedBy=multi-user.target

```
Just make it works by typing : systemctl enable dt.service && systectl start dt.service

On client side, your systemd boot file like this, named with named with dt.service location at 
/etc/systemd/system/dt.service

```
[Unit]
Description=dt
After=network.target
Requires=network.target

[Service]
TimeoutStartSec=0
ExecStart=/usr/bin/docker run --rm --name dt -p 8070:8070 netroby/alpine-dog-tunnel /usr/bin/dtunnel_lite -service your.remote.server:123 -local :8070 -auth verystrongpassword2
Restart=always

[Install]
WantedBy=multi-user.target

```


Just make client works by typing : systemctl enable dt.service && systectl start dt.service

If every thing ok, you will have socks5 proxy service listen on your local 0.0.0.0:8070

Configure your proxy or application with it .

You can also using polipo to provided http proxy forward

A small polipo configure file  /etc/polipo/config

```
proxyAddress = "0.0.0.0"    # IPv4 only
allowedClients = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8
socksParentProxy = "127.0.0.1:8070"
socksProxyType = socks5

```