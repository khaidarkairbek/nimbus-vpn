use mio::{net::UdpSocket, unix::SourceFd};
use std::{net::SocketAddr, collections::HashMap, os::fd::AsRawFd};
use num_bigint::BigInt;
use mio::{Events, Poll as Mio_Poll, Interest, Token};
use crate::dev::{Device, Message};
use crate::tun::TunDevice;

pub fn server_side (server_addr : SocketAddr, tun_num : Option<u8>, server_private_key : BigInt) -> Result<(), String> {   
    let mut server_socket = UdpSocket::bind(server_addr).map_err(|e| e.to_string())?;

    Ok(())
}

pub fn client_side (client_addr : SocketAddr, server_addr: SocketAddr, tun_num: Option<u8>, client_private_key: BigInt ) -> Result<(), String> {
    let mut client_socket = UdpSocket::bind(client_addr).map_err(|e| e.to_string())?;

    let tun = TunDevice::create(tun_num).map_err(|e| e.to_string())?; 
    tun.up();
    let tun_raw_fd = tun.file.as_raw_fd(); 
    let mut tun_socket = SourceFd(&tun_raw_fd);

    let mut poll = Mio_Poll::new().map_err(|e| e.to_string())?; 
    let mut events = Events::with_capacity(1024); 
    poll.registry().register(&mut client_socket, Token(0), Interest::READABLE).map_err(|e| e.to_string())?;
    poll.registry().register(&mut tun_socket, Token(1), Interest::READABLE | Interest::WRITABLE).map_err(|e| e.to_string())?; 

    let mut client = Device::Client { client_socket: client_socket, server_addr: server_addr, tun: tun, shared_secret_key: None, private_key: client_private_key}; 

    client.initiate_handshake()?;

    loop {
        poll.poll(&mut events, None).map_err(|e| e.to_string())?; // Replace with async tokio 
        for event in &events {
            match event.token() {
                Token(0) => { 
                    let msg = client.read_socket()?;
                    match msg {
                        Message::Response { .. } => {
                            let shared_secret_key = client.process_response(&msg)?; 
                            println!("Shared secret key is {}", shared_secret_key);
                            client.set_shared_secret_key(shared_secret_key, None)?; 
                        }, 
                        Message::PayLoad { data } => {
                            client.write_tun(data)?;
                        }
                        _ => ()  // Implement data transmission
                    }
                }, 
                Token(1) => {
                    let mut buffer = [0u8; 2000];
                    match client.read_tun(&mut buffer) {
                        Ok(len ) => {

                            if len > 0  {
                                // TODO: Encryption/decryption protocols need to be established

                                client.write_socket(&buffer[..len])?;
                                // Implement TUN logic
                            }
                            
                        }, 
                        Err(_) => ()
                    };
                }, 
                _ => ()
            }
        }
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
        let tun = TunDevice::create(None).unwrap(); 
        tun.up(); 

        let mut poll = Mio_Poll::new().unwrap();
        let mut events = Events::with_capacity(1024);
        poll.registry().register(&mut client_socket, Token(0), Interest::READABLE).unwrap();

        let client = Device::Client {client_socket: client_socket, server_addr: server_addr, tun : tun, shared_secret_key : None, private_key : client_private_key};
        client.initiate_handshake().unwrap();

        let mut shared_secret_key = None;

        for _ in 0..10 {
            poll.poll(&mut events, Some(Duration::from_secs(1))).unwrap();
            for event in &events {
                if event.token() == Token(0) && event.is_readable() {
                    let mut buffer = [0; 2000];
                    if let Device::Client { client_socket, ..} = &client {

                        let len = client_socket.recv(&mut buffer).unwrap();
                        if let Ok(msg) = serde_json::from_slice::<Message>(&buffer[..len]) {
                            shared_secret_key = Some(client.process_response(&msg).unwrap());
                            println!("The shared secret key is {:?}", shared_secret_key);
                            return;
                        }

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
        let tun = TunDevice::create(None).unwrap(); 
        tun.up(); 

        let mut poll = Mio_Poll::new().unwrap();
        let mut events = Events::with_capacity(1024);

        poll.registry().register(&mut server_socket, Token(0), Interest::READABLE).unwrap();

        let server = Device::Server {server_socket: server_socket, client_key_map: HashMap::new(), tun : tun, private_key : server_private_key};

        let mut shared_secret_key = None;

        for _ in 0..10 {  // Try for 10 iterations
            poll.poll(&mut events, Some(Duration::from_secs(1))).unwrap();
            for event in &events {
                if event.token() == Token(0) && event.is_readable() {
                    if let Device::Server { server_socket, ..} = &server {
                        
                        let mut buffer = [0; 2000];
                        let (len, client_addr) = server_socket.recv_from(&mut buffer).unwrap();
                        if let Ok(msg) = serde_json::from_slice::<Message>(&buffer[..len]) {
                            shared_secret_key = Some(server.process_request( &client_addr,  msg).unwrap());
                            println!("The shared secret key is {:?}", shared_secret_key);
                            return;
                        }

                    }
                }
            }
        }
        assert!(shared_secret_key.is_some(), "Failed to establish shared secret key");
    }
}
