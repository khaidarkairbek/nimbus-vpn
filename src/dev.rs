use mio::net::UdpSocket;
use crate::tun::TunDevice;
use std::{collections::HashMap, net::SocketAddr};
use serde::{Deserialize, Serialize};
use serde_json;
use num_bigint::BigInt;
use crate::crypto::{encrypt_data, decrypt_data};


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


// Diffie Hellman Key Exchange implementation
pub const DH_MODULUS: &'static str = "23";  // Placeholder values for testing
pub const DH_BASE: &'static str = "5";

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
pub fn process_request (&self, client_addr: &SocketAddr, request_msg: Message) -> Result<BigInt, String> {
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

    pub fn write_socket(&mut self, data: &[u8]) -> Result<(), String> {
        match self {
            Device::Client { client_socket: socket, server_addr, shared_secret_key, ..} => {
                let encrypted_data = match shared_secret_key {
                    Some(key) => encrypt_data(data, key)?,
                    None => data.to_vec(), // If there's no key, just send the data as-is
                };
                let mut bytes_left = encrypted_data.len();
                while bytes_left > 0 {
                    let bytes_written = socket.send_to(&encrypted_data, *server_addr).map_err(|e| e.to_string())?;
                    bytes_left = bytes_left - bytes_written;
                }
                Ok(())
            },
            _ => Err("Unimplemented yet".to_string())  // TODO: Implement server side logic
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

}
