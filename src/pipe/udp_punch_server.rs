use std::io;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::prelude::*;

pub struct udp_punch_server;
impl udp_punch_server {
    pub async fn listen(&self, addr: &str) -> io::Result<()> {
        let mut listener = TcpListener::bind(addr).await?;

        println!("listening ok");
        let mut delay = tokio::time::delay_for(Duration::from_secs(15));

        loop {
            tokio::select! {
                _ = &mut delay => {
                    panic!("timeout");
                }
                res = listener.accept() => {
                    let (mut socket, _)=res.unwrap();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];

                        // In a loop, read data from the socket and write the data back.
                        loop {
                            let n = match socket.read(&mut buf).await {
                                // socket closed
                                Ok(n) if n == 0 => return,
                                Ok(n) => n,
                                Err(e) => {
                                    println!("failed to read from socket; err = {:?}", e);
                                    return;
                                }
                            };

                            // Write the data back
                            if let Err(e) = socket.write_all(&buf[0..n]).await {
                                println!("failed to write to socket; err = {:?}", e);
                                return;
                            }
                        }
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::udp_punch_server;
    #[tokio::test]
    async fn test_listen() {
        let s = udp_punch_server;
        s.listen("127.0.0.1:1234").await;
    }
}
