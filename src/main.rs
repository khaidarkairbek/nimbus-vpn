use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Result;
use clap::Parser;

use std::net::Ipv4Addr;

use crate::{cli::Mode, client::Client, server::Server, tun::config::Configuration};

mod cli;
mod client;
mod comm;
mod crypto;
mod error;
mod server;
mod tun;

fn main() -> Result<()> {
    let args = cli::Cli::parse();
    env_logger::init();

    let stop = Arc::new(AtomicBool::new(false));

    match args.mode {
        Mode::Client {
            address,
            port,
            local_port,
        } => {
            let server_addr = format!("{address}:{port}")
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid server address '{address}:{port}': {e}"))?;
            let mut config = Configuration::default();
            config.address = Some(Ipv4Addr::new(10, 0, 0, 2));
            config.destination = Some(Ipv4Addr::new(10, 0, 0, 1));
            config.netmask = Some(Ipv4Addr::new(255, 255, 255, 255));
            Client::init(local_port, server_addr, &config)?.start(stop)?;
        }
        Mode::Server { port } => {
            let mut config = Configuration::default();
            config.address = Some(Ipv4Addr::new(10, 0, 0, 1));
            config.destination = Some(Ipv4Addr::new(10, 0, 0, 2));
            config.netmask = Some(Ipv4Addr::new(255, 255, 255, 255));
            Server::init(port, &config)?.start(stop)?;
        }
    }

    Ok(())
}
