use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;

pub struct UDPClientInfo {
    dst_addr: SocketAddr,
}
pub struct UDPServerInfo {
    client_pipes: HashMap<String, UDPPipe>,
}
impl UDPServerInfo {
    fn default() -> UDPServerInfo {
        UDPServerInfo {
            client_pipes: HashMap::new(),
        }
    }
}
enum UDPPipeInfo {
    UDPServer(UDPServerInfo),
    UDPClient(UDPClientInfo),
}
pub struct UDPPipe {
    pub socket: UdpSocket,
    pipe_info: UDPPipeInfo,
}
impl UDPPipe {
    #[allow(dead_code)]
    async fn listen(addr: &str) -> Result<UDPPipe, Box<dyn Error>> {
        let mut socket = UdpSocket::bind(addr).await?;
        let mut pipe = UDPPipe {
            socket,
            pipe_info: UDPPipeInfo::UDPServer(UDPServerInfo::default()),
        };
        Ok(pipe)
    }
    async fn read_event_loop(mut self) {
        let mut buf = [0u8; 1024];

        // In a loop, read data from the socket and write the data back.
        loop {
            match &self.socket.recv_from(&mut buf).await {
                Ok((l, addr)) => {
                    println!("recv len:{}", l);
                    &self.socket.send_to(&buf[0..*l], addr).await;
                }
                Err(e) => {
                    eprintln!("failed to read from socket; err = {:?}", e);
                    break;
                }
            };
        }
    }
    async fn dial<'a>(
        local_addr: Option<&str>,
        addr: &str,
        punch_server: &str,
    ) -> Result<UDPPipe, Box<dyn Error>> {
        let mut socket = UdpSocket::bind(local_addr.unwrap_or("0.0.0.0:0")).await?;
        let addr = addr.parse::<SocketAddr>()?;
        println!("begin connect {}", addr);
        socket.connect(addr).await?; //udp bind
        println!("connect ok");
        let mut buf = vec![0; 1024];
        let client_info = UDPClientInfo { dst_addr: addr };
        Ok(UDPPipe {
            socket: socket,
            pipe_info: UDPPipeInfo::UDPClient(client_info),
        })
    }
    async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf).await
    }
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.recv(buf).await
    }
    async fn close(self) {
        let _ = self;
    }
}
#[cfg(test)]
mod test {
    use super::UDPPipe;
    use std::time::Duration;
    use tokio::time::delay_for;

    #[tokio::test]
    async fn udp_dial_test() {
        println!("this is a test");
        let c = UDPPipe::dial(None, "127.0.0.1:1234", "").await;
        if let Ok(mut sock) = c {
            println!("send/recv 0");
            sock.send(b"test").await;
            let mut buf = [0u8; 1024];
            // sock.recv(&mut buf).await.map(|l| {
            //     println!("send/recv 1, {:?}", l);
            // });
            sock.send(b"test222222222").await;
            //sock.recv(&mut buf).await.map(|l| {
            //    println!("send/recv 2, {:?}", l);
            //});
            tokio::spawn(async move {
                let mut delay = delay_for(Duration::from_millis(1000));
                loop {
                    tokio::select! {
                        _ = &mut delay => {
                            println!("operation timed out");
                            break;
                        }
                        ret = tokio::future::poll_fn(|cx| sock.socket.poll_recv_from(cx, &mut buf)) => {
                            match ret {
                                Ok((l, addr)) => {
                                    println!("recv len:{}", l);
                                    //&sock.socket.send_to(&buf[0..l], addr).await;
                                }
                                _ => {

                                }
                            }
                        }
                    }
                }
                println!("quit");
            });

            let mut interval = tokio::time::interval(Duration::from_millis(1000));
            let mut i = 0;
            loop {
                interval.tick().await;
                i += 1;
                println!("main thread loop;{}", i);
                if i > 4 {
                    break;
                }
            }
            delay_for(Duration::from_millis(10000)).await;
        //sock.close();
        } else {
            println!("dial error");
        }
    }
    #[tokio::test]
    async fn udp_listen_test() {
        println!("this is a test");
        let c = UDPPipe::listen("127.0.0.1:1234").await;
        if let Ok(s) = c {
            s.read_event_loop().await;
        }
    }
}
