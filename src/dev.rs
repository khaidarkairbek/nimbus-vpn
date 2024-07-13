use mio::net::UdpSocket;
use crate::{crypto::{generate_public_key, generate_shared_key}, tun::TunDevice};
use std::{collections::HashMap, net::SocketAddr};
use serde::{Deserialize, Serialize};
use serde_json;
use num_bigint::BigInt;
use crate::crypto::{encrypt_data, decrypt_data};


#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Request { client_public_key: BigInt },
    Response { client_id: u8, server_public_key: BigInt },
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
        client_key_map : HashMap<u8, (SocketAddr, BigInt)>, 
        tun : TunDevice, 
        private_key : BigInt, 
        available_ids : Vec<u8>
    }
}


pub enum SecretData<'a> {
    SharedSecretKey(&'a BigInt), 
    SharedSecretClientData(&'a SocketAddr, &'a BigInt)
}

impl Device {
    pub fn set_shared_secret_key (&mut self, new_key: BigInt, client_info: Option<(u8, SocketAddr)>) -> Result<(), String>{
        match self {
            Device::Client { shared_secret_key , ..} => {
                *shared_secret_key = Some(new_key);
                Ok(())
            },
            Device::Server { client_key_map, ..} => {
                if let Some((id, addr)) = client_info {
                    client_key_map.insert(id, (addr, new_key));
                    Ok(())
                } else {
                    Err("Client address is not specified for a key".to_string())
                }
            }
        }
    }

    pub fn get_shared_secret_key (&self, client_id : Option<u8>) -> Result<SecretData, String>{
        match self {
            Device::Client { shared_secret_key , ..} => {
                match shared_secret_key.as_ref() {
                    None => Err("Shared secret key not specified for a client".to_string()), 
                    Some(shared_key) => Ok(SecretData::SharedSecretKey(shared_key))
                }
            }, 
            Device::Server { client_key_map, .. } => {
                if let Some(id) = client_id {
                    match client_key_map.get(&id) {
                        None => Err("Client address is not found in client key map".to_string()), 
                        Some((client_addr, shared_key)) => Ok(SecretData::SharedSecretClientData(client_addr, shared_key))
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

    pub fn write_socket (&mut self, data: &[u8], client_id: Option<u8>) -> Result<(), String> {
        match self {
            Device::Client { client_socket: socket , server_addr, ..} => {
                let mut bytes_left = data.len(); 
                while bytes_left > 0 {
                    let bytes_written = socket.send_to(data, *server_addr).map_err(|e| e.to_string()).unwrap(); 
                    bytes_left = bytes_left - bytes_written;
                }
                Ok(())
            }, 
            Device::Server { server_socket: socket, client_key_map, ..} => {

                if let Some(id) = client_id {
                    match client_key_map.get(&id) {
                        Some((client_addr, _)) => {
                            let mut bytes_left = data.len(); 
                            while bytes_left > 0 {
                                let bytes_written = socket.send_to(data, *client_addr).map_err(|e| e.to_string()).unwrap(); 
                                bytes_left = bytes_left - bytes_written;
                            };
                            Ok(())
                        }, 
                        None => {
                            Err("No client found for a given client id for server".to_string())
                        }
                    }
                } else {
                    Err("No client id specified for server".to_string())
                }
            }
        }
    }

    pub fn read_socket (&mut self) -> Result<(SocketAddr, Message), String> {
        match self {
            Device::Client { client_socket: socket , ..} | Device::Server { server_socket : socket, .. } => {
                let mut buffer = [0; 2000];
                let (len, from_addr) = socket.recv_from(&mut buffer).map_err(|e| e.to_string())?;
                let msg = serde_json::from_slice::<Message>(&buffer[..len]).map_err(|e| e.to_string())?;
                Ok((from_addr, msg))
            },
        } 
    }

    // Initiates the handshake by calculating the client public key using Diffie Hellman algorithm and send the request with the public key to the server
    pub fn initiate_handshake (&self) -> Result<(), String> {
        match self {
            Device::Client {
                client_socket,
                server_addr,
                private_key,
                ..
            } => {
                let client_public_key = generate_public_key(private_key);

                let request_msg = Message::Request { client_public_key }; //create a request message

                let serialized = serde_json::to_string(&request_msg).map_err(|e| e.to_string())?; //serialize the message to json

                client_socket.send_to(serialized.as_bytes(), *server_addr).map_err(|e| e.to_string())?;

                println!("request sent to the server {}", server_addr);

                Ok(())
            }
            _ => Err("handshake can be initiated by client only".to_string()),
        }
    }

    // Processes the response from the server after initiating handshake and calculates shared secret key
    pub fn process_response (&self, response_msg: Message) -> Result<BigInt, String> {
        match self {
            Device::Client {private_key, tun,..} => {
                match response_msg {
                    Message::Response { client_id, server_public_key,  } => {
                        tun.up(Some(client_id));
                        let shared_secret_key = generate_shared_key(&server_public_key, private_key);
                        Ok(shared_secret_key)
                    }, 
                    _ => Err("Response message is not a response".to_string())
                }
            }, 
            _ => Err("Response can be sent to client only".to_string())
        }
    }

    // Processes the request from the client after initiating handshake, sends the response and calculates shared secret key
    pub fn process_request (&mut self, client_addr: &SocketAddr, request_msg: Message) -> Result<(u8, BigInt), String> {
        match self {
            Device::Server {server_socket, private_key, available_ids,..} => {
                match request_msg {
                    Message::Request { client_public_key } => {
                        let server_public_key = generate_public_key(private_key); 
                        match available_ids.pop() {
                            Some(client_id) => {
                                let response_msg = Message::Response { client_id, server_public_key };
                                let serialized = serde_json::to_string(&response_msg).map_err(|e| e.to_string())?;
                                
                                server_socket.send_to(serialized.as_bytes(), client_addr.clone()).map_err(|e| e.to_string())?;
                                
                                println!("Response sent to the client {}", client_addr);
                                
                                let shared_secret_key = generate_shared_key(&client_public_key, private_key);

                                Ok((client_id, shared_secret_key))
                            }, 
                            None => {
                                Err("No space available for new connection".to_string())
                            }
                        }
                    },
                    _ => Err("Request message is not a request".to_string())
                }
            }, 
            _ => Err("Request can be sent to server only".to_string())
        }
    }
}
