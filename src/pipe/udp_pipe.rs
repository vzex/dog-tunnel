use std::error::Error;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
pub struct udp_pipe {}
impl udp_pipe {
    #[allow(dead_code)]
    async fn dial<'a>(
        local_port: u8,
        addr: &str,
        punch_server: &str,
    ) -> Result<udp_pipe, Box<dyn Error>> {
        let mut socket = UdpSocket::bind("0.0.0.0:0").await?;
        let addr = addr.parse::<SocketAddr>()?;
        let content = "test".as_bytes();
        socket.send_to(content as &[u8], addr).await?;
        let mut buf = vec![0; 1024];
        socket
            .recv_from(&mut buf)
            .await
            .map(|(n, src)| println!("recv {:?}", buf.get(0..n)));
        Ok(udp_pipe {})
    }
    async fn close(self) {}
}
#[cfg(test)]
mod test {
    use super::udp_pipe;
    #[tokio::test]
    async fn udp_dial_test() {
        println!("this is a test");
        udp_pipe::dial(0, "127.0.0.1:1234", "")
            .await
            .map_err(|e| println!("error:{}", e));
    }
}
