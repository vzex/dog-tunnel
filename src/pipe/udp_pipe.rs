use std::collections::HashMap;
//use std::error::Error;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub struct UdpServerPipe {
    client_pipes: HashMap<SocketAddr, UdpClientPipe>,
}
pub struct UdpClientPipe {
    //pub socket: Arc<Mutex<UdpSocket>>,
    send_socket: tokio::net::udp::SendHalf,
    recv_socket: tokio::net::udp::RecvHalf,
    send_channel: mpsc::Sender<Vec<u8>>,
    recv_channel: mpsc::Receiver<Vec<u8>>,
    dst_addr: SocketAddr,
    send_handler: Option<tokio::task::JoinHandle<()>>,
    server_pipe: bool,
}
impl<'a> UdpServerPipe<'a> {
    #[allow(dead_code)]
    async fn listen(addr: &str) -> Result<Arc<UdpServerPipe<'a>>, Box<dyn std::error::Error>> {
        let mut socket = UdpSocket::bind(addr).await?;
        let (tx_send, rx_send) = mpsc::channel::<Vec<u8>>(100);
        let (tx_recv, rx_recv) = mpsc::channel::<Vec<u8>>(100);
        let (mut rs, mut ws) = socket.split();
        let mut pipe = Arc::new(UdpServerPipe {
            client_pipes: HashMap::new(),
        });
        let recv_pipe = pipe.clone();
        tokio::spawn(async move {
            //self.send_event_loop(wp, rx_send, Some()).await;
            recv_pipe.recv_event_loop(rs, ws, rx_recv).await;
        });
        //let custom_error = Error::new(ErrorKind::Other, "oh no!");

        //Err(Box::new(custom_error))
        Ok(pipe)
    }
    async fn recv_event_loop(
        self,
        rs: tokio::net::udp::RecvHalf,
        ws: tokio::net::udp::SendHalf,
        rx_recv: mpsc::Receiver<Vec<u8>>,
    ) {
        let mut buf = vec![0; 1024];
        while let Ok((l, addr)) = rs.recv_from(&mut buf).await {
            let &mut pipe = self
                .client_pipes
                .entry(addr)
                .or_insert(UdpClientPipe::new(rs, ws, addr, true));
            //pipe.write()
        }
    }
}
impl UdpClientPipe {
    fn new(
        rs: tokio::net::udp::RecvHalf,
        ws: tokio::net::udp::SendHalf,
        addr: SocketAddr,
        server_pipe: bool,
    ) -> UdpClientPipe {
        let (tx_send, rx_send) = mpsc::channel::<Vec<u8>>(100);
        let (tx_recv, rx_recv) = mpsc::channel::<Vec<u8>>(100);
        let mut pipe = UdpClientPipe {
            recv_socket: rs,
            send_socket: ws,
            send_channel: tx_send,
            recv_channel: rx_recv,
            dst_addr: addr,
            send_handler: None,
            server_pipe: server_pipe,
        };
        pipe.send_handler = Some(tokio::spawn(async move {
            pipe.send_event_loop(ws, rx_recv, Some(addr));
        }));
        pipe
    }
    async fn send_event_loop(
        self,
        socket: tokio::net::udp::SendHalf,
        mut rx: mpsc::Receiver<Vec<u8>>,
        addr: Option<SocketAddr>,
    ) {
        // In a loop, read data from the socket and write the data back.
        while let Some(buf) = rx.recv().await {
            if let Some(_addr) = addr {
                socket.send_to(&mut buf, &_addr).await;
            } else {
                socket.send(&mut buf).await;
            }
        }
    }
    async fn dial<'a>(
        local_addr: Option<&str>,
        addr: &str,
        punch_server: &str,
    ) -> Result<UdpClientPipe, Box<dyn Error>> {
        let mut socket = UdpSocket::bind(local_addr.unwrap_or("0.0.0.0:0")).await?;
        let addr = addr.parse::<SocketAddr>()?;
        println!("begin connect {}", addr);
        socket.connect(addr).await?; //udp bind
        println!("connect ok");
        let mut buf = vec![0; 1024];
        let (rs, ws) = socket.split();
        Ok(UdpClientPipe::new(rs, ws, addr, false))
    }
    async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send_socket.send(buf).await
    }
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv_socket.recv(buf).await
    }
    async fn close(self) {
        let _ = self;
    }
}
#[cfg(test)]
mod test {
    use super::UdpClientPipe;
    use super::UdpServerPipe;
    use std::time::Duration;
    use tokio::time::delay_for;

    #[tokio::test]
    async fn udp_dial_test() {
        println!("this is a test");
        let c = UdpClientPipe::dial(None, "127.0.0.1:1234", "").await;
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
        let c = UdpServerPipe::listen("127.0.0.1:1234").await;
        if let Ok(s) = c {
            //s.read_event_loop().await;
        }
    }
}
