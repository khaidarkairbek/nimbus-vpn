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
    PayLoad { data: Vec<u8> }
}

pub enum Device {
    Client {
        client_socket : UdpSocket,
        server_addr : SocketAddr, 
        tun : TunDevice,
        shared_secret_key : Option<BigInt>, 
        private_key : BigInt
    }, 
    Server {
        server_socket : UdpSocket, 
        client_key_map : HashMap<SocketAddr, BigInt>, 
        tun : TunDevice, 
        private_key : BigInt
    }
}

impl Device {
    pub fn set_shared_secret_key (&mut self, new_key: BigInt, client_addr: Option<SocketAddr>) -> Result<(), String>{
        match self {
            Device::Client { shared_secret_key , ..} => {
                *shared_secret_key = Some(new_key);
                Ok(())
            },
            Device::Server { client_key_map, ..} => {
                if let Some(addr) = client_addr {
                    client_key_map.insert(addr, new_key);
                    Ok(())
                } else {
                    Err("Client address is not specified for a key".to_string())
                }
            }
        }
    }

    pub fn get_shared_secret_key (&self, client_addr : Option<SocketAddr>) -> Result<&BigInt, String>{
        match self {
            Device::Client { shared_secret_key , ..} => {
                match shared_secret_key.as_ref() {
                    None => Err("Shared secret key not specified for a client".to_string()), 
                    Some(shared_key) => Ok(shared_key)
                }
            }, 
            Device::Server { client_key_map, .. } => {
                if let Some(addr) = client_addr {
                    match client_key_map.get(&addr) {
                        None => Err("Client address is not found in client key map".to_string()), 
                        Some(shared_key) => Ok(shared_key)
                    }
                } else {
                    Err("Client address is not specified for a key".to_string())
                }
            }
        }
    }

    pub fn write_tun (&mut self, data: Vec<u8>) -> Result<(), String> {
        match self {
            Device::Client { tun, ..} | Device::Server { tun, .. } => {
                let mut bytes_left = data.len(); 
                while bytes_left > 0 {
                    let bytes_written = tun.write(&data).map_err(|e| e.to_string())?; 
                    bytes_left = bytes_left - bytes_written;
                }
                Ok(())
            }
        }
    }

    pub fn read_tun (&mut self, buffer: &mut [u8]) -> Result<usize, String> {
        match self {
            Device::Client { tun, ..} | Device::Server { tun, .. } => {
                let len = tun.read(buffer).map_err(|e| e.to_string())?; 
                Ok(len)
            }
        }
    }

    pub fn write_socket (&mut self, data: &[u8]) -> Result<(), String> {
        match self {
            Device::Client { client_socket: socket , server_addr, ..} => {
                let mut bytes_left = data.len(); 
                while bytes_left > 0 {
                    let bytes_written = socket.send_to(data, *server_addr).map_err(|e| e.to_string()).unwrap(); 
                    bytes_left = bytes_left - bytes_written;
                }
                Ok(())
            }, 
            _ => Err("Unimplemented yet".to_string())  // TODO: Need to find a way to differentiate packets coming to server TUN
        }
    }

    pub fn read_socket (&mut self) -> Result<Message, String> {
        match self {
            Device::Client { client_socket: socket , ..} | Device::Server { server_socket : socket, .. } => {
                let mut buffer = [0; 2000];
                let len = socket.recv(&mut buffer).map_err(|e| e.to_string())?;
                let msg = serde_json::from_slice::<Message>(&buffer[..len]).map_err(|e| e.to_string())?;
                Ok(msg)
            }
        } 
    }

    // Initiates the handshake by calculating the client public key using Diffie Hellman algorithm and send the request with the public key to the server
    pub fn initiate_handshake (&self) -> Result<(), String> {
        match self {
            Device::Client { client_socket, server_addr , private_key, ..} => {
                let p: BigInt = DH_MODULUS.parse().unwrap();
                let g: BigInt = DH_BASE.parse().unwrap();

                let client_public_key = g.modpow(private_key, &p);

                let request_msg = Message::Request { client_public_key };

                let serialized = serde_json::to_string(&request_msg).map_err(|e| e.to_string())?;

                client_socket.send_to(serialized.as_bytes(), server_addr.clone()).map_err(|e| e.to_string())?;

                println!("Request sent to the server {}", server_addr);

                Ok(())
            }, 
            _ => Err("Handshake can be initiated by client only".to_string())
        }
    }

    // Processes the response from the server after initiating handshake and calculates shared secret key
    pub fn process_response (&self, response_msg: &Message) -> Result<BigInt, String> {
        match self {
            Device::Client {private_key, ..} => {
                let p: BigInt = DH_MODULUS.parse().unwrap();

                match response_msg {
                    Message::Response { server_public_key,  } => {
                        Ok(server_public_key.modpow(private_key, &p))
                    }, 
                    _ => Err("Response message is not a response".to_string())
                }
            }, 
            _ => Err("Response can be sent to client only".to_string())
        }
    }

    // Processes the request from the client after initiating handshake, sends the response and calculates shared secret key
    fn process_request (&self, client_addr: &SocketAddr, request_msg: Message) -> Result<BigInt, String> {
        match self {
            Device::Server {server_socket, private_key, ..} => {
                let p: BigInt = DH_MODULUS.parse().unwrap();
                let g: BigInt = DH_BASE.parse().unwrap();

                match request_msg {
                    Message::Request { client_public_key } => {
                        let server_public_key = g.modpow(private_key, &p);
                        let response_msg = Message::Response { server_public_key };
                        let serialized = serde_json::to_string(&response_msg).map_err(|e| e.to_string())?;
                        
                        server_socket.send_to(serialized.as_bytes(), client_addr.clone()).map_err(|e| e.to_string())?;
                        
                        println!("Response sent to the client {}", client_addr);

                        Ok(client_public_key.modpow(private_key, &p))
                    },
                    _ => Err("Request message is not a request".to_string())
                }
            }, 
            _ => Err("Request can be sent to server only".to_string())
        }
    }
}

// Diffie Hellman Key Exchange implementation
const DH_MODULUS: &'static str = "23";  // Placeholder values for testing
const DH_BASE: &'static str = "5";

fn client_side (client_addr : SocketAddr, server_addr: SocketAddr, tun_num: Option<u8>, client_private_key: BigInt ) -> Result<(), String> {
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

fn main () {
    let client_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let server_addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
    let client_private_key: BigInt = "24".parse().unwrap();
    client_side(client_addr, server_addr, None, client_private_key).unwrap();
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
