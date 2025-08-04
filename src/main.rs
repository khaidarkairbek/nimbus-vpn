use clap::Parser;

use crate::{cli::Mode, client::Client, server::Server};

mod cli;
mod crypto;
mod comm;
mod error;
mod server; 
mod client;
mod tun;  

fn main() {
    let args = cli::Cli::parse(); 

    match args.mode {
        Mode::Client { address, port, local_port } => {
            let server_addr = format!("{address}:{port}").parse().unwrap(); 
            let mut client = Client::init(local_port, server_addr).unwrap();

            client.start().unwrap(); 
        }, 
        Mode::Server { port } => {
            let mut server = Server::init(port).unwrap(); 
            server.start().unwrap(); 
        }
    }
}


