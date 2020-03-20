use std::collections::HashMap;
//use std::error::Error;
use std::io;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use tokio::net::udp::{RecvHalf, SendHalf};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

pub struct UdpServerPipe {
    socket: Arc<Mutex<UdpSocket>>,
    //   recv_socket: tokio::net::udp::RecvHalf,
    client_pipes: Arc<Mutex<HashMap<SocketAddr, UdpClientPipe>>>,
}
//enum UdpClientSendSocket {
//    Ref(UdpClientSocketRef),
//    Real(UdpClientSocketReal),
//}
type UdpClientSendSocket = Arc<Mutex<UdpSocket>>;
pub struct UdpClientPipe {
    socket: UdpClientSendSocket,
    r_main_send_channel: mpsc::Sender<Vec<u8>>,
    r_main_recv_channel: mpsc::Receiver<Vec<u8>>,
    dst_addr: SocketAddr,
    send_handler: Option<tokio::task::JoinHandle<()>>,
    is_server: bool,
}
impl UdpServerPipe {
    #[allow(dead_code)]
    async fn listen(addr: &str) -> Result<UdpServerPipe, Box<dyn std::error::Error>> {
        let mut socket = UdpSocket::bind(addr).await?;
        let (tx_send, rx_send) = mpsc::channel::<Vec<u8>>(100);
        let (tx_recv, rx_recv) = mpsc::channel::<Vec<u8>>(100);
        //let shared_socket = Arc::new(socket);
        //let recv_socket = tokio::net::udp::RecvHalf(shared_socket.clone());
        let mut server_pipe = UdpServerPipe {
            //recv_socket: recv_socket,
            socket: Arc::new(Mutex::new(socket)),
            client_pipes: Arc::new(Mutex::new(HashMap::new())),
        };
        //let pipe = Arc::new(server_pipe);
        let mut recv_pipe = server_pipe.socket.clone();
        tokio::spawn(server_pipe.read_loop());
        //let custom_error = Error::new(ErrorKind::Other, "oh no!");

        //Err(Box::new(custom_error))
        Ok(server_pipe)
    }
    async fn read_loop(&mut self) {
        let mut buf = vec![0u8; 1024];
        while let Ok((l, addr)) = self.socket.lock().unwrap().recv_from(&mut buf).await {
            let pipe = self
                .client_pipes
                .lock()
                .unwrap()
                .entry(addr)
                .or_insert(UdpClientPipe::new_server_side(self.socket.clone(), addr).unwrap());
            pipe.r_main_send_channel.send(buf[0..l].to_vec());
        }
    }
}
impl UdpClientPipe {
    async fn new_client_side(
        local_addr: Option<&str>,
        addr: SocketAddr,
    ) -> Result<UdpClientPipe, Box<dyn std::error::Error>> {
        let mut socket = UdpSocket::bind(local_addr.unwrap_or("0.0.0.0:0")).await?;
        println!("begin connect {}", addr);
        socket.connect(addr).await?; //udp bind
        let (tx_main_recv, rx_main_recv) = mpsc::channel::<Vec<u8>>(100);

        let socket_pipe = Arc::new(Mutex::new(socket));
        let mut pipe = UdpClientPipe {
            is_server: false,
            socket: socket_pipe,
            r_main_send_channel: tx_main_recv,
            r_main_recv_channel: rx_main_recv,
            dst_addr: addr,
            send_handler: None,
        };

        let recv_pipe = socket_pipe.clone();

        pipe.send_handler = Some(tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            while let Ok(l) = recv_pipe.lock().unwrap().recv(&mut buf).await {
                pipe.r_main_send_channel.send(buf[0..l].to_vec());
            }
            pipe.r_main_send_channel.send(vec![]);
        }));
        Ok(pipe)
    }
    fn new_server_side(
        shared_socket: UdpClientSendSocket,
        addr: SocketAddr,
    ) -> Result<UdpClientPipe, Box<dyn std::error::Error>> {
        let (tx_main_recv, rx_main_recv) = mpsc::channel::<Vec<u8>>(100);
        let mut pipe = UdpClientPipe {
            is_server: true,
            socket: shared_socket,
            r_main_send_channel: tx_main_recv,
            r_main_recv_channel: rx_main_recv,
            dst_addr: addr,
            send_handler: None,
        };
        Ok(pipe)
    }
    async fn recv_event_loop(recv: &mut RecvHalf) {}
    async fn send(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.is_server {
            self.socket
                .lock()
                .unwrap()
                .send_to(buf, &self.dst_addr)
                .await
        } else {
            self.socket.lock().unwrap().send(buf).await
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
        let mut c = UdpClientPipe::new_client_side(None, dest).await;
        if let Ok(ref mut sock) = c {
            println!("send/recv 0");
            sock.send(b"test").await;
            let mut buf = [0u8; 1024];
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
        let c = UdpServerPipe::listen("127.0.0.1:1234").await;
        if let Ok(s) = c {
            //s.read_event_loop().await;
        }
    }
}
