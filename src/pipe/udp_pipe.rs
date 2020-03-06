use std::error::Error;
use std::io;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
pub struct udp_pipe {
    socket: UdpSocket,
    dst_addr: SocketAddr,
}
impl udp_pipe {
    #[allow(dead_code)]
    async fn dial<'a>(
        local_port: u8,
        addr: &str,
        punch_server: &str,
    ) -> Result<udp_pipe, Box<dyn Error>> {
        let mut socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = addr.parse::<SocketAddr>()?;
        println!("begin connect {}", addr);
        socket.connect(addr).await?; //udp bind
        println!("connect ok");
        let mut buf = vec![0; 1024];
        Ok(udp_pipe {
            socket: socket,
            dst_addr: addr,
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
    use super::udp_pipe;
    #[tokio::test]
    async fn udp_dial_test() {
        println!("this is a test");
        let c = udp_pipe::dial(0, "127.0.0.1:1234", "").await;
        if let Ok(mut sock) = c {
            println!("send/recv 0");
            sock.send(b"test").await;
            let mut buf = [0u8; 1024];
            sock.recv(&mut buf).await.map(|l| {
                println!("send/recv 1, {:?}", l);
            });
            sock.send(b"test222222222").await;
            sock.recv(&mut buf).await.map(|l| {
                println!("send/recv 2, {:?}", l);
            });
            sock.close();
        } else {
            println!("dial error");
        }
    }
}
