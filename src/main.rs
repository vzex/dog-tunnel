use tokio::net::TcpStream;
use tokio::prelude::*;

use clap::Clap;

#[derive(Clap)]
#[clap(version = "0.1", author = "vzex")]
struct Opts {
#[clap(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: i32,
#[clap(subcommand)]
	subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
#[clap(name = "c", about = "client mode", version = "0.1", author = "vzex")]
	Client(ClientOpts),
#[clap(name = "s", about = "server mode", version = "0.1", author = "vzex")]
	Server(ServerOpts),
#[clap(name = "p", about = "punch server mode", version = "0.1", author = "vzex")]
	PunchServer(PunchServerOpts),
#[clap(name = "cli", about = "cli mode", version = "0.1", author = "vzex")]
	CliCmd(CliOpts),
}

#[derive(Clap)]
struct ClientOpts {
#[clap(short = "s", long = "svc", default_value = "127.0.0.1:8888")]
	service: String,
#[clap(short = "a", long = "admin", default_value = "127.0.0.1:8887")]
	admin_addr: String,
}
#[derive(Clap)]
struct ServerOpts {
#[clap(short = "s", long = "svc", default_value = "127.0.0.1:8888")]
	service: String,
#[clap(short = "a", long = "admin", default_value = "127.0.0.1:8887")]
	admin_addr: String,
}
#[derive(Clap)]
struct PunchServerOpts {
#[clap(long = "addr", default_value = ":8889")]
	addr: String,
#[clap(long = "admin", default_value = "127.0.0.1:8887")]
	admin_addr: String,
}
#[derive(Clap)]
struct CliOpts{
#[clap(short = "a", long = "addr", default_value = "127.0.0.1:8887")]
	admin_addr: String,
}
#[tokio::main]
async fn main() {
	let opts: Opts = Opts::parse();
	match &opts.subcmd {
		SubCommand::Client(t) => {
			println!("connect to {}", t.service);
			println!("local admin addr is {}", t.admin_addr);
			client_main(t, &opts).await;
		}
		_ => {
			println!("not support yet");
			return;
		}
	}
}

async fn client_main(cmd: &ClientOpts, opts: &Opts) {
	let mut stream = TcpStream::connect(cmd.service.clone()).await.unwrap();
	println!("connect ok");

	let result = stream.write(b"hello world\n").await;
	println!("wrote to stream; success={:?}", result.is_ok());
}
