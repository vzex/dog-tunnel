mod cmd;
use cmd::{cli, client, punch_server, server};

mod common;
use common::flags_info;

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
