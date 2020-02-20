#![cfg_attr(feature = "nowarnings", allow(dead_code))]
#![cfg_attr(feature = "nowarnings", allow(unused_variables))]
#![cfg_attr(feature = "nowarnings", allow(unused_imports))]
//use crate::cmd;
use dogtunnel::cmd::{cli, client, punch_server, server};

use dogtunnel::common::flags_info;

#[tokio::main]
async fn main() {
    let opts = flags_info::opts_parse();
    match &opts.subcmd {
        flags_info::SubCommand::Client(t) => {
            client::sub_main(t, &opts).await;
        }
        flags_info::SubCommand::Server(t) => {
            server::sub_main(t, &opts).await;
        }
        _ => {
            println!("not support yet");
            return;
        }
    }
}
