use tokio::net::TcpStream;
use tokio::prelude::*;

use crate::common::flags_info;
pub async fn sub_main(cmd: &flags_info::ClientOpts, opts: &flags_info::Opts) {
    println!("connect to {}", cmd.service);
    println!("local admin addr is {}", cmd.admin_addr);
    let mut stream = TcpStream::connect(cmd.service.clone()).await.unwrap();
    println!("connect ok");

    let result = stream.write(b"hello world\n").await;
    println!("wrote to stream; success={:?}", result.is_ok());
}
