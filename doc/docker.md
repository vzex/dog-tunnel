# Run dog tunnel with docker container

First things, you need make sure you have installed docker on your linux environment.
Following instruction was testing under ubuntu 14.04 or above.

You need install docker on both your server side and client side

## server side


```
docker run -d --restart=always --name=dog-tunnel-server -p 0.0.0.0:8443:8443/udp netroby/alpine-dog-tunnel /usr/bin/dtunnel_lite -service 0.0.0.0:8443 -auth verystrongpassword2
```

## client side

Replace your service ip with your.remote.server, and run this command.

```
docker run -d --restart=always --name=dog-tunnel-client -p 0.0.0.0:8070:8070 netroby/alpine-dog-tunnel /usr/bin/dtunnel_lite -service your.remote.server:8443 -local :8070 -auth verystrongpassword2
```
If every thing ok, you will have socks5 proxy service listen on your local 0.0.0.0:8070
