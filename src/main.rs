mod comm; 
mod tun; 
mod dev;
mod cli; 

use std::{net::SocketAddr, process};
use num_bigint::BigInt;
use comm::{client_side, server_side};
use clap::Parser;
use crate::cli::Mode;


fn main () {
    let args = cli::Cli::parse();

    match args.mode {
        Mode::Client { address, port, key, local_port, tun_num } => {
            let server_addr: SocketAddr = format!("{}:{}", address, port).parse().unwrap(); 
            let client_addr: SocketAddr = match local_port {
                None => "0.0.0.0:0".parse().unwrap(), 
                Some(port) => format!("0.0.0.0:{}", port).parse().unwrap()
            }; 
            let client_private_key: BigInt = key.parse().unwrap(); 
            client_side(client_addr, server_addr, tun_num, client_private_key).unwrap();
        }, 
        Mode::Server { port, key, tun_num }=> {
            let server_addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap(); 
            // the public ip of the server: curl -s https://ifconfig.me
            let public_addr: String = String::from_utf8(process::Command::new("curl").arg("-s").arg("https://ifconfig.me").output().unwrap().stdout).unwrap(); 
            println!("Server address is: {:?}", public_addr);
            let server_private_key: BigInt = key.parse().unwrap(); 
            server_side(server_addr, tun_num, server_private_key).unwrap();
        }
    }
}