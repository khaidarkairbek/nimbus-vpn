use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Result;
use clap::Parser;

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
            Client::init(local_port, server_addr, &Configuration::default())?.start(stop)?;
        }
        Mode::Server { port } => {
            Server::init(port, &Configuration::default())?.start(stop)?;
        }
    }

    Ok(())
}
