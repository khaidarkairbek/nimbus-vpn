mod comm; 
mod tun; 
mod dev;

use std::net::SocketAddr;
use num_bigint::BigInt;
use comm::client_side;


fn main () {
    let client_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
    let client_private_key: BigInt = "24".parse().unwrap();
    client_side(client_addr, server_addr, None, client_private_key).unwrap();
}