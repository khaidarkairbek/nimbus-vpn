use mio::{net::UdpSocket, unix::SourceFd};
use tun::TunDevice;
use std::{collections::HashMap, env, net::SocketAddr, os::fd::AsRawFd};
use serde::{Deserialize, Serialize};
use serde_json;
use num_bigint::BigInt;
use mio::{Events, Poll as Mio_Poll, Interest, Token};

mod tun;

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Request { client_public_key: BigInt },
    Response { server_public_key: BigInt }, 
}

pub enum Device {
    Client { 
        client_addr : SocketAddr, 
        server_addr : SocketAddr, 
        tun : TunDevice,
        shared_secret_key : Option<BigInt>
    }, 
    Server {
        server_addr : SocketAddr, 
        client_key_map : HashMap<SocketAddr, BigInt>, 
        tun : Option<TunDevice>
    }
}

impl Device {
    pub fn set_shared_secret_key (&mut self, new_key: BigInt) {
        if let Device::Client {shared_secret_key, ..} = self {
            *shared_secret_key = Some(new_key)
        }
    }

    pub fn get_shared_secret_key (&self) -> Option<&BigInt>{
        if let Device::Client { shared_secret_key, ..} = self {
            shared_secret_key.as_ref()
        } else {
            None
        }
    }
}

// Diffie Hellman Key Exchange implementation
const DH_MODULUS: &'static str = "23";  // Placeholder values for testing
const DH_BASE: &'static str = "5";

// Initiates the handshake by calculating the client public key using Diffie Hellman algorithm and send the request with the public key to the server
fn initiate_handshake (client_socket: &UdpSocket, server_addr: &SocketAddr, client_private_key: &BigInt) -> Result<(), String> {
    let p: BigInt = DH_MODULUS.parse().unwrap();
    let g: BigInt = DH_BASE.parse().unwrap();

    let client_public_key = g.modpow(client_private_key, &p);

    let request_msg = Message::Request { client_public_key };

    let serialized = serde_json::to_string(&request_msg).map_err(|e| e.to_string())?;

    client_socket.send_to(serialized.as_bytes(), server_addr.clone()).map_err(|e| e.to_string())?;

    println!("Request sent to the server {}", server_addr);

    Ok(())
}

// Processes the response from the server after initiating handshake and calculates shared secret key
fn process_response (response_msg: &Message, client_private_key: &BigInt) -> Result<BigInt, String> {
    let p: BigInt = DH_MODULUS.parse().unwrap();

    match response_msg {
        Message::Response { server_public_key } => {
            Ok(server_public_key.modpow(client_private_key, &p))
        }, 
        _ => Err("Request message is not a request".to_string())
    }
}

// Processes the request from the client after initiating handshake, sends the response and calculates shared secret key
fn process_request (server_socket: &UdpSocket, client_addr: &SocketAddr, server_private_key: &BigInt, request_msg: Message) -> Result<BigInt, String> {
    let p: BigInt = DH_MODULUS.parse().unwrap();
    let g: BigInt = DH_BASE.parse().unwrap();

    match request_msg {
        Message::Request { client_public_key } => {
            let server_public_key = g.modpow(server_private_key, &p);
            let response_msg = Message::Response { server_public_key };
            let serialized = serde_json::to_string(&response_msg).map_err(|e| e.to_string())?;
            
            server_socket.send_to(serialized.as_bytes(), client_addr.clone()).map_err(|e| e.to_string())?;
            
            println!("Response sent to the client {}", client_addr);

            Ok(client_public_key.modpow(server_private_key, &p))
        },
        _ => Err("Request message is not a request".to_string())
    }
}

fn client_side (client_addr : SocketAddr, server_addr: SocketAddr, tun_num: Option<u8>, client_private_key: BigInt ) {
    let mut client_socket = UdpSocket::bind(client_addr).unwrap();

    let mut tun = TunDevice::create(tun_num).unwrap(); 
    tun.up();
    let tun_raw_fd = tun.file.as_raw_fd(); 
    let mut tun_socket = SourceFd(&tun_raw_fd);

    let mut client = Device::Client { client_addr: client_addr, server_addr: server_addr, tun: tun, shared_secret_key: None}; 

    let mut poll = Mio_Poll::new().unwrap(); 
    let mut events = Events::with_capacity(1024); 
    poll.registry().register(&mut client_socket, Token(0), Interest::READABLE).unwrap();
    poll.registry().register(&mut tun_socket, Token(1), Interest::READABLE | Interest::WRITABLE).unwrap(); 

    initiate_handshake(&client_socket, &server_addr, &client_private_key).unwrap();

    loop {
        poll.poll(&mut events, None).unwrap(); 
        for event in &events {
            match event.token() {
                Token(0) => {
                    let mut buffer = [0; 2000];
                    let len = client_socket.recv(&mut buffer).unwrap();
                    let msg = serde_json::from_slice::<Message>(&buffer[..len]).unwrap(); 
                    match &msg {
                        Message::Response { .. } => {
                            let shared_secret_key = process_response(&msg, &client_private_key).unwrap(); 
                            client.set_shared_secret_key(shared_secret_key); 
                        }, 
                        _ => ()  // Implement data transmission
                    }
                }, 
                Token(1) => {
                    // Implement TUN logic
                }, 
                _ => ()
            }
        }
    }       
}

fn main () {
    let args: Vec<String> = env::args().collect(); 

    let device_type = &args[1]; 
    if device_type == "client" {

    } else {

    }
    
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_client_handshake() {
        let client_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let server_addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let client_private_key: BigInt = "24".parse().unwrap();

        let mut client_socket = UdpSocket::bind(client_addr).unwrap();

        let mut poll = Mio_Poll::new().unwrap();
        let mut events = Events::with_capacity(1024);

        poll.registry().register(&mut client_socket, Token(0), Interest::READABLE).unwrap();

        initiate_handshake(&client_socket, &server_addr, &client_private_key).unwrap();

        let mut shared_secret_key = None;

        for _ in 0..10 {
            poll.poll(&mut events, Some(Duration::from_secs(1))).unwrap();
            for event in &events {
                if event.token() == Token(0) && event.is_readable() {
                    let mut buffer = [0; 2000];
                    let len = client_socket.recv(&mut buffer).unwrap();
                    if let Ok(msg) = serde_json::from_slice::<Message>(&buffer[..len]) {
                        shared_secret_key = Some(process_response(&msg, &client_private_key).unwrap());
                        println!("The shared secret key is {:?}", shared_secret_key);
                        return;
                    }
                }
            }
        }
        assert!(shared_secret_key.is_some(), "Failed to establish shared secret key");
    }

    #[test]
    fn test_server_handshake() {
        let server_addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let server_private_key: BigInt = "70".parse().unwrap();

        let mut server_socket = UdpSocket::bind(server_addr).unwrap();

        let mut poll = Mio_Poll::new().unwrap();
        let mut events = Events::with_capacity(1024);

        poll.registry().register(&mut server_socket, Token(0), Interest::READABLE).unwrap();

        let mut shared_secret_key = None;

        for _ in 0..10 {  // Try for 10 iterations
            poll.poll(&mut events, Some(Duration::from_secs(1))).unwrap();
            for event in &events {
                if event.token() == Token(0) && event.is_readable() {
                    let mut buffer = [0; 2000];
                    let (len, client_addr) = server_socket.recv_from(&mut buffer).unwrap();
                    if let Ok(msg) = serde_json::from_slice::<Message>(&buffer[..len]) {
                        shared_secret_key = Some(process_request(&server_socket, &client_addr, &server_private_key, msg).unwrap());
                        println!("The shared secret key is {:?}", shared_secret_key);
                        return;
                    }
                }
            }
        }
        assert!(shared_secret_key.is_some(), "Failed to establish shared secret key");
    }
}
