use clap::Clap;

#[derive(Clap)]
#[clap(version = "0.1", author = "vzex")]
pub struct Opts {
    #[clap(short = "v", long = "verbose", parse(from_occurrences))]
    pub verbose: i32,
    #[clap(subcommand)]
    pub subcmd: SubCommand,
}
pub fn opts_parse() -> Opts {
    Opts::parse()
}

#[derive(Clap)]
pub enum SubCommand {
    #[clap(name = "c", about = "client mode", version = "0.1", author = "vzex")]
    Client(ClientOpts),
    #[clap(name = "s", about = "server mode", version = "0.1", author = "vzex")]
    Server(ServerOpts),
    #[clap(
        name = "p",
        about = "punch server mode",
        version = "0.1",
        author = "vzex"
    )]
    PunchServer(PunchServerOpts),
    #[clap(name = "cli", about = "cli mode", version = "0.1", author = "vzex")]
    CliCmd(CliOpts),
}

#[derive(Clap)]
pub struct ClientOpts {
    #[clap(short = "s", long = "svc", default_value = "127.0.0.1:8888")]
    pub service: String,
    #[clap(short = "a", long = "admin", default_value = "127.0.0.1:8887")]
    pub admin_addr: String,
}
#[derive(Clap)]
pub struct ServerOpts {
    #[clap(short = "s", long = "svc", default_value = "127.0.0.1:8888")]
    pub service: String,
    #[clap(short = "a", long = "admin", default_value = "127.0.0.1:8887")]
    pub admin_addr: String,
}
#[derive(Clap)]
pub struct PunchServerOpts {
    #[clap(long = "addr", default_value = ":8889")]
    pub addr: String,
    #[clap(long = "admin", default_value = "127.0.0.1:8887")]
    pub admin_addr: String,
}
#[derive(Clap)]
pub struct CliOpts {
    #[clap(short = "a", long = "addr", default_value = "127.0.0.1:8887")]
    pub admin_addr: String,
}
