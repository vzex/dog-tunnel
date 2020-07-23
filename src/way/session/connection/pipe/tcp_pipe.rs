//use std::sync::Mutex;
use tokio::sync::Mutex;

use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
//use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TryRecvError;
use tokio::sync::oneshot;

pub enum ClientEvent {
    Connect(bool),
    Recv(Vec<u8>),
    Dis(),
}
pub enum ServerEvent {
    Listen(bool),
    Accept(u32),
    Recv(u32, Vec<u8>),
    Dis(u32),
}

pub struct SendData {
    pub id: u32,
    pub data: Vec<u8>,
}
pub struct TcpServerPipe {
    client_pipes: Arc<Mutex<HashMap<u32, TcpClientPipe>>>,
    recv_event: mpsc::UnboundedReceiver<ServerEvent>,
    send_event: mpsc::UnboundedSender<ServerEvent>,
    send_data_event: Option<mpsc::UnboundedSender<SendData>>,
    //recv_data_event: mpsc::UnboundedReceiver<SendData>,
}

//#[derive(Debug, Clone)]
pub struct TcpClientPipe {
    r_main_recv_channel: mpsc::UnboundedReceiver<Vec<u8>>,
    w_main_send_channel: mpsc::UnboundedSender<Vec<u8>>,

    r_main_send_channel: mpsc::UnboundedReceiver<Vec<u8>>,
    w_main_recv_channel: mpsc::UnboundedSender<Vec<u8>>,
    is_server: bool,
    is_connect: bool,

    recv_event: mpsc::UnboundedReceiver<ClientEvent>,
    send_event: mpsc::UnboundedSender<ClientEvent>,
}
impl TcpServerPipe {
    #[allow(dead_code)]
    pub fn init() -> TcpServerPipe {
        let (w, mut r) = mpsc::unbounded_channel::<ServerEvent>();
        TcpServerPipe {
            client_pipes: Arc::new(Mutex::new(HashMap::new())),
            recv_event: r,
            send_event: w,
            send_data_event: None, //cw,
                                   //recv_data_event: cr,
        }
    }
    pub fn get_sender(&self) -> Option<mpsc::UnboundedSender<SendData>> {
        if let Some(ref s) = self.send_data_event {
            Some(s.clone())
        } else {
            None
        }
    }
    pub fn send(&mut self, id: u32, d: &[u8]) {
        if let Some(ref mut c) = self.send_data_event {
            c.send(SendData {
                id,
                data: Vec::from(d),
            });
        }
    }
    pub fn listen_with_callback(&mut self, addr: &str) {
        let w = self.send_event.clone();
        let wp = self.send_event.clone();
        let pipes = self.client_pipes.clone();
        let (wd, rd) = mpsc::unbounded_channel::<SendData>();
        self.send_data_event = Some(wd);
        let a = String::from(addr);
        tokio::spawn(async move {
            println!("begin listen");
            //let wp = w.clone();
            if let Ok(s) = Self::listen(pipes, a.as_str(), w, rd).await {
                println!("begin listen ok");
                wp.send(ServerEvent::Listen(true));
            } else {
                wp.send(ServerEvent::Listen(false));
                println!("begin listen not ok");
            }
        });
    }
    pub fn loop_for_event(
        &mut self,
        mut on_listen: impl FnMut(&mut Self, bool),
        mut on_accept: impl FnMut(&mut Self, u32),
        mut on_dis: impl FnMut(&mut Self, u32),
        mut on_recv: impl FnMut(&mut Self, u32, Vec<u8>),
    ) {
        loop {
            match self.recv_event.try_recv() {
                Ok(ev) => match ev {
                    ServerEvent::Listen(ok) => {
                        on_listen(self, ok);
                    }
                    ServerEvent::Accept(id) => {
                        on_accept(self, id);
                    }
                    ServerEvent::Dis(id) => {
                        on_dis(self, id);
                    }
                    ServerEvent::Recv(id, d) => {
                        on_recv(self, id, d);
                    }
                },
                Empty => {
                    break;
                }
                Closed => {
                    break;
                }
            }
        }
    }

    pub async fn listen(
        cpipes: Arc<Mutex<HashMap<u32, TcpClientPipe>>>,
        addr: &str,
        event: mpsc::UnboundedSender<ServerEvent>,
        mut rc: mpsc::UnboundedReceiver<SendData>,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let mut listener = TcpListener::bind(addr).await?;

        let (mut tx_main_recv, mut rx_main_recv) = mpsc::unbounded_channel::<u32>();
        //let pipe = Arc::new(server_pipe);
        let ev = event.clone();
        let cpipesa = cpipes.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            let mut id = 0u32;
            while let Ok((client_stream, _)) = listener.accept().await {
                //todo remove from pipes
                println!("recv from {:?}", client_stream);
                let addr = client_stream.peer_addr().unwrap();
                let mut clients = cpipesa.lock().await;

                id += 1;
                let mut c = TcpClientPipe::new_server_side(
                    client_stream,
                    id,
                    tx_main_recv.clone(),
                    ev.clone(),
                )
                .unwrap();
                ev.send(ServerEvent::Accept(id));
                clients.insert(id, c);
            }
        });
        let cpipesb = cpipes.clone();
        tokio::spawn(async move {
            while let Some(id) = rx_main_recv.recv().await {
                println!("server remove pipe:{}", id);
                event.send(ServerEvent::Dis(id));
                cpipesb.lock().await.remove(&id);
            }
        });
        let cpipesb = cpipes.clone();
        tokio::spawn(async move {
            while let Some(d) = rc.recv().await {
                if let Some(c) = cpipesb.lock().await.get_mut(&d.id) {
                    c.send(d.data.as_slice());
                }
            }
        });
        Ok(true)
    }
}
impl TcpClientPipe {
    pub fn init() -> TcpClientPipe {
        let (w, mut r) = mpsc::unbounded_channel::<ClientEvent>();
        let (mut tx_main_recv, rx_main_recv) = mpsc::unbounded_channel::<Vec<u8>>();
        let (mut tx_main_send, mut rx_main_send) = mpsc::unbounded_channel::<Vec<u8>>();
        TcpClientPipe {
            is_connect: false,
            is_server: false,
            r_main_recv_channel: rx_main_recv,
            w_main_recv_channel: tx_main_recv,
            w_main_send_channel: tx_main_send,
            r_main_send_channel: rx_main_send,
            send_event: w,
            recv_event: r,
        }
    }
    pub fn dial(&mut self, addr: &str) {
        let dest = addr.parse::<SocketAddr>().unwrap();
        let (wp, mut rp) = oneshot::channel::<Option<TcpClientPipe>>();
        let tx_main_recv = self.send_event.clone();
        let mut send_event = self.send_event.clone();
        let (w, r) = mpsc::unbounded_channel::<Vec<u8>>();
        self.w_main_send_channel = w;
        tokio::spawn(async move {
            if let Ok(_) = Self::new_client_side(tx_main_recv, r, None, dest).await {
                send_event.send(ClientEvent::Connect(true));
            } else {
                send_event.send(ClientEvent::Connect(false));
            }
        });
    }
    pub fn loop_for_event(
        &mut self,
        mut on_connect: impl FnMut(&mut Self, bool),
        mut on_dis: impl FnMut(),
        mut on_recv: impl FnMut(&mut Self, Vec<u8>),
    ) {
        loop {
            match self.recv_event.try_recv() {
                Ok(ev) => match ev {
                    ClientEvent::Connect(ok) => {
                        on_connect(self, ok);
                    }
                    ClientEvent::Dis() => {
                        on_dis();
                    }
                    ClientEvent::Recv(d) => {
                        on_recv(self, d);
                    }
                },
                Empty => {
                    break;
                }
                Closed => {
                    break;
                }
            }
        }
    }

    pub async fn new_client_side(
        tx_main_recv: mpsc::UnboundedSender<ClientEvent>,
        mut rx_main_send: mpsc::UnboundedReceiver<Vec<u8>>,
        local_addr: Option<&str>,
        addr: SocketAddr,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        println!("begin connect {}", addr);
        let mut socket = TcpStream::connect(addr).await?;

        let (mut r, mut w) = socket.into_split();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            println!("try begin recv");
            while let Ok(l) = r.read(&mut buf).await {
                if l <= 0 {
                    break;
                }
                println!("client recv {}", l);
                tx_main_recv.send(ClientEvent::Recv(buf[0..l].to_vec()));
            }
            println!("try end recv");
            tx_main_recv.send(ClientEvent::Dis());
        });
        tokio::spawn(async move {
            while let Some(d) = rx_main_send.recv().await {
                println!("try send data {}", d.len());
                w.write(d.as_slice()).await;
                println!("try send data ok");
            }
            println!("write channel close");
            w.shutdown().await;
        });
        Ok(true)
    }
    fn new_server_side(
        socket: TcpStream,
        pipe_id: u32,
        inform_chan: mpsc::UnboundedSender<u32>,
        recv_chan: mpsc::UnboundedSender<ServerEvent>,
    ) -> Result<TcpClientPipe, Box<dyn std::error::Error>> {
        let (mut tx_main_recv, rx_main_recv) = mpsc::unbounded_channel::<Vec<u8>>();
        let (mut tx_main_send, mut rx_main_send) = mpsc::unbounded_channel::<Vec<u8>>();
        let (mut tx_main_send2, mut rx_main_send2) = mpsc::unbounded_channel::<Vec<u8>>();
        let addr = socket.peer_addr().unwrap();
        let (mut r, mut w) = socket.into_split();
        let (cw, mut cr) = mpsc::unbounded_channel::<ClientEvent>();
        let ww = tx_main_recv.clone();
        let mut pipe = TcpClientPipe {
            is_connect: true,
            is_server: true,
            r_main_recv_channel: rx_main_recv,
            w_main_send_channel: tx_main_send,
            r_main_send_channel: rx_main_send2, //Some/None
            w_main_recv_channel: ww,
            send_event: cw,
            recv_event: cr,
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];
            println!("try begin recv2");
            while let Ok(l) = r.read(&mut buf).await {
                if l <= 0 {
                    break;
                }
                println!("client2 recv {}", l);
                recv_chan.send(ServerEvent::Recv(pipe_id, buf[0..l].to_vec()));
                println!("client2 recv 2 {}", l);
            }
            println!("try end recv2");
            tx_main_recv.send(vec![]);
            inform_chan.send(pipe_id);
        });
        tokio::spawn(async move {
            while let Some(d) = rx_main_send.recv().await {
                println!("try send data2 {}", d.len());
                w.write(d.as_slice()).await;
                println!("try send data2 ok");
            }
            println!("write channel close");
            w.shutdown().await;
        });
        Ok(pipe)
    }
    pub fn send(&mut self, buf: &[u8]) {
        self.w_main_send_channel.send(Vec::from(buf));
    }
    pub fn recv(&mut self) -> Option<Vec<u8>> {
        loop {
            match self.r_main_recv_channel.try_recv() {
                Ok(d) => {
                    return Some(d);
                }
                Empty => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Closed => {
                    return None;
                }
            }
        }
    }
    pub fn try_recv(&mut self) -> Option<Vec<u8>> {
        match self.r_main_recv_channel.try_recv() {
            Ok(d) => Some(d),
            Empty => Some(vec![0u8; 0]),
            Closed => None,
        }
    }
    pub fn close(&mut self) {
        self.send(&[0u8; 0]);
    }
}
#[cfg(test)]
mod test {
    use super::TcpClientPipe;
    use super::TcpServerPipe;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::time::delay_for;

    use std::sync::{Arc, Mutex};
    use tokio::runtime::Runtime;
    #[tokio::test]
    async fn tcp_dial_test() {
        println!("this is a test");
        let dest = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();
        let mut c = TcpClientPipe::init();
        c.dial("127.0.0.1:1234");
        let mut a = true;
        loop {
            c.loop_for_event(
                |_c, ok| {
                    println!("on connect result {:?}", ok);
                    if ok {
                        println!("send/recv 0");
                        _c.send(b"test");
                    }
                },
                || {
                    println!("on dis");
                    a = false;
                },
                |_c, d| {
                    println!("on recv {:?}", d);
                    _c.send(b"test222222222");
                },
            );
            //std::thread::sleep(std::time::Duration::from_millis(100));
            delay_for(Duration::from_millis(100)).await;
        }
    }
    use tokio::sync::mpsc;
    #[tokio::test]
    async fn tcp_listen_test() {
        println!("this is a test");
        let mut s = TcpServerPipe::init();
        s.listen_with_callback("127.0.0.1:1234");
        loop {
            s.loop_for_event(
                |_s, ok| {
                    println!("on listen result {:?}", ok);
                },
                |_s, cid| {
                    println!("on accept {:?}", cid);
                    _s.send(cid, b"wowo");
                },
                |_s, cid| {
                    println!("on dis {:?}", cid);
                },
                |_s, cid, d| {
                    println!("on recv {}:{:?}", cid, d);
                },
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
            //delay_for(Duration::from_millis(100)).await;
        }
        //if let Ok(s) = c {}
        println!("this is a test end");
    }
}
