use std::net::Ipv4Addr;

use clap::Parser;

use crate::{cli::Mode, client::Client, server::Server, tun::config::Configuration};

mod cli;
mod crypto;
mod comm;
mod error;
mod server; 
mod client;
mod tun;  

fn main() {
    let args = cli::Cli::parse(); 

    let address_ip: Ipv4Addr = "10.0.0.3".parse().unwrap();
    let destination_ip: Ipv4Addr = "142.250.31.100".parse().unwrap();
    let netmask: Ipv4Addr = "255.255.255.255".parse().unwrap();

    match args.mode {
        Mode::Client { address, port, local_port } => {
            let server_addr = format!("{address}:{port}").parse().unwrap();

            let mut client_dev_config = Configuration::default();
            client_dev_config.address = Some(address_ip);
            client_dev_config.destination = Some(destination_ip);
            client_dev_config.netmask = Some(netmask);

            let mut client = Client::init(local_port, server_addr, &client_dev_config).unwrap();

            client.start().unwrap(); 
        }, 
        Mode::Server { port } => {
            let mut server_dev_config = Configuration::default();
            server_dev_config.address = Some(destination_ip);
            server_dev_config.destination = Some(address_ip);
            server_dev_config.netmask = Some(netmask);

            let mut server = Server::init(port, &server_dev_config).unwrap(); 
            server.start().unwrap(); 
        }
    }
}


