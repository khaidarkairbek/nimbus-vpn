use clap::Parser;

use crate::{cli::Mode, client::Client, server::Server, tun::config::Configuration};

mod cli;
mod client;
mod comm;
mod crypto;
mod error;
mod server;
mod tun;

fn main() {
    let args = cli::Cli::parse();
    env_logger::init(); 

    match args.mode {
        Mode::Client {
            address,
            port,
            local_port,
        } => {
            let server_addr = format!("{address}:{port}").parse().unwrap();
            let mut client =
                Client::init(local_port, server_addr, &Configuration::default()).unwrap();
            client.start().unwrap();
        }
        Mode::Server { port } => {
            let mut server = Server::init(port, &Configuration::default()).unwrap();
            server.start().unwrap();
        }
    }
}
