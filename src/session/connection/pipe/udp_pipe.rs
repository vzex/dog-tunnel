use std::collections::HashMap;
//use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

pub struct UdpServerPipe {
    socket: Arc<Mutex<UdpSocket>>,
    //   recv_socket: tokio::net::udp::RecvHalf,
    client_pipes: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
}
//enum UdpClientSendSocket {
//    Ref(UdpClientSocketRef),
//    Real(UdpClientSocketReal),
//}
//type UdpClientSendSocket = Arc<Mutex<UdpSocket>>;
pub struct UdpClientPipe {
    socket: Arc<Mutex<UdpSocket>>,
    r_main_send_channel: Option<mpsc::Sender<Vec<u8>>>,
    r_main_recv_channel: mpsc::Receiver<Vec<u8>>,
    dst_addr: SocketAddr,
    send_handler: Option<tokio::task::JoinHandle<()>>,
    is_server: bool,
}
impl UdpServerPipe {
    #[allow(dead_code)]
    async fn listen(
        addr: &str,
        on_accept: fn(UdpClientPipe),
        channel_size: usize,
    ) -> Result<UdpServerPipe, Box<dyn std::error::Error>> {
        let mut socket = UdpSocket::bind(addr).await?;
        let mut csize = channel_size;
        socket.connect("asdasd");
        if (channel_size == 0) {
            csize = 100;
        }
        let (tx_send, rx_send) = mpsc::channel::<Vec<u8>>(csize);
        let (tx_recv, rx_recv) = mpsc::channel::<Vec<u8>>(csize);
        //let shared_socket = Arc::new(socket);
        //let recv_socket = tokio::net::udp::RecvHalf(shared_socket.clone());
        //let (recv_socket, send_socket) = socket.split();
        let shared_socket = Arc::new(Mutex::new(socket));
        let mut server_pipe = UdpServerPipe {
            //recv_socket: recv_socket,
            socket: shared_socket.clone(),
            client_pipes: Arc::new(Mutex::new(HashMap::new())),
        };
        //let pipe = Arc::new(server_pipe);
        let cpipes = server_pipe.client_pipes.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            while let Ok((l, addr)) = shared_socket.lock().await.recv_from(&mut buf).await {
                println!("recv from {:?}, {:?}", l, addr);
                let mut clients = cpipes.lock().await;

                let pipe = clients.entry(addr).or_insert_with(|| {
                    let mut p =
                        UdpClientPipe::new_server_side(shared_socket.clone(), addr, 0).unwrap();
                    let c = p.r_main_send_channel;
                    p.r_main_send_channel = None;
                    on_accept(p);
                    c.unwrap()
                });
                println!(
                    "recv inform to my client {}, {:?}",
                    l,
                    pipe.send(buf[0..l].to_vec()).await
                );
            }
        });
        //let custom_error = Error::new(ErrorKind::Other, "oh no!");

        //Err(Box::new(custom_error))
        Ok(server_pipe)
    }
}
impl UdpClientPipe {
    async fn new_client_side(
        local_addr: Option<&str>,
        addr: SocketAddr,
        channel_size: usize,
    ) -> Result<UdpClientPipe, Box<dyn std::error::Error>> {
        let mut socket = UdpSocket::bind(local_addr.unwrap_or("0.0.0.0:0")).await?;
        println!("begin connect {}", addr);
        socket.connect(addr).await?; //udp bind
        let mut csize = channel_size;
        if channel_size == 0 {
            csize = 100;
        }
        let (mut tx_main_recv, rx_main_recv) = mpsc::channel::<Vec<u8>>(csize);

        let shared_socket = Arc::new(Mutex::new(socket));
        let mut pipe = UdpClientPipe {
            is_server: false,
            socket: shared_socket.clone(),
            r_main_send_channel: None,
            r_main_recv_channel: rx_main_recv,
            dst_addr: addr,
            send_handler: None,
        };

        //pipe.send_handler
        let mut handler = Some(tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            println!("try begin recv");
            while let Ok(l) = shared_socket.lock().await.recv(&mut buf).await {
                println!("client recv {}", l);
                tx_main_recv.send(buf[0..l].to_vec()).await;
            }
            println!("try end recv");
            tx_main_recv.send(vec![]).await;
        }));
        pipe.send_handler = handler;
        Ok(pipe)
    }
    fn new_server_side(
        socket: Arc<Mutex<UdpSocket>>,
        addr: SocketAddr,
        channel_size: usize,
    ) -> Result<UdpClientPipe, Box<dyn std::error::Error>> {
        let mut csize = channel_size;
        if (channel_size == 0) {
            csize = 100;
        }
        let (tx_main_recv, rx_main_recv) = mpsc::channel::<Vec<u8>>(csize);
        let mut pipe = UdpClientPipe {
            is_server: true,
            socket: socket,
            r_main_send_channel: Some(tx_main_recv),
            r_main_recv_channel: rx_main_recv,
            dst_addr: addr,
            send_handler: None,
        };
        //do test
        //if let Some(mut f) = pipe.r_main_send_channel {
        //    //f.send(b"asassa".to_vec());
        //    pipe.r_main_send_channel = None;
        //    tokio::spawn(async move {
        //        f.send(b"hello".to_vec()).await;
        //    });
        //}
        //test server client!!!!!! will remove
        Ok(pipe)
    }
    async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.is_server {
            self.socket.lock().await.send_to(buf, &self.dst_addr).await
        } else {
            self.socket.lock().await.send(buf).await
        }
    }
    async fn recv(&mut self) -> Option<Vec<u8>> {
        self.r_main_recv_channel.recv().await
    }
    async fn close(self) {
        let _ = self;
    }
}
#[cfg(test)]
mod test {
    use super::UdpClientPipe;
    use super::UdpServerPipe;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::time::delay_for;

    use std::sync::{Arc, Mutex};
    #[tokio::test]
    async fn udp_dial_test() {
        println!("this is a test");
        let dest = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();
        let mut c = UdpClientPipe::new_client_side(None, dest, 0).await;
        if let Ok(ref mut sock) = c {
            println!("send/recv 0");
            sock.send(b"test").await;
            sock.recv().await.map(|v| {
                println!("send/recv 1, {:?}", v);
            });
            sock.send(b"test222222222").await;
            sock.recv().await.map(|v| {
                println!("send/recv 2, {:?}", v);
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
        let c = UdpServerPipe::listen(
            "127.0.0.1:1234",
            |cc| {
                println!("on accept {:?}", cc.dst_addr);
                tokio::spawn(async move {
                    let mut ccc = cc;
                    loop {
                        let d = ccc.recv().await;
                        if let Some(dd) = d {
                            if dd.len() == 0 {
                                break;
                            }
                            println!("send back {:?}", ccc.send(&dd[0..]).await);
                        }
                    }
                });
            },
            0,
        )
        .await;
        //if let Ok(s) = c {}
        delay_for(Duration::from_millis(10000)).await;
        println!("this is a test end");
    }
}
