use mio::net::UdpSocket;
use crate::{crypto::{generate_public_key, generate_shared_key}, error::LogicError, tun::TunDevice};
use std::{collections::HashMap, net::SocketAddr, process, str};
use serde::{Deserialize, Serialize};
use serde_json;
use num_bigint::BigInt;
use anyhow::{Result, bail};

use crate::error::{
    ServerError::*, 
    ClientError::*, 
    SocketError::*, 
    LogicError::*, 
    CommError::*
};


#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Request { client_public_key: BigInt },
    Response { client_id: u8, server_public_key: BigInt },
    PayLoad { client_id: u8, data: Vec<u8> }
}

pub enum Device {
    Client {
        client_socket : UdpSocket,
        server_addr : SocketAddr, 
        tun : TunDevice,
        shared_secret_key : Option<BigInt>, 
        private_key : BigInt, 
        id: Option<u8>, 
        default_gateway: Option<String>
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
    pub fn set_shared_secret_key (&mut self, new_key: BigInt, client_info: Option<(u8, SocketAddr)>) -> Result<()>{
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
                    bail!(ClientInfoSetError)
                }
            }
        }
    }

    pub fn get_shared_secret_key (&self, client_id : Option<u8>) -> Result<SecretData>{
        match self {
            Device::Client { shared_secret_key , ..} => {
                match shared_secret_key.as_ref() {
                    None => bail!(SharedKeyGetError), 
                    Some(shared_key) => Ok(SecretData::SharedSecretKey(shared_key))
                }
            }, 
            Device::Server { client_key_map, .. } => {
                if let Some(id) = client_id {
                    match client_key_map.get(&id) {
                        None => bail!(ClientInfoNotFound), 
                        Some((client_addr, shared_key)) => Ok(SecretData::SharedSecretClientData(client_addr, shared_key))
                    }
                } else {
                    bail!(ClientInfoGetError)
                }
            }
        }
    }


    pub fn write_tun (&mut self, data: Vec<u8>) -> Result<()> {
        match self {
            Device::Client { tun, ..} | Device::Server { tun, .. } => {
                let mut bytes_left = data.len(); 
                while bytes_left > 0 {
                    let bytes_written = tun.write(&data)?; 
                    bytes_left = bytes_left - bytes_written;
                }
                Ok(())
            }
        }
    }

    pub fn read_tun (&mut self, buffer: &mut [u8]) -> Result<usize> {
        match self {
            Device::Client { tun, ..} | Device::Server { tun, .. } => {
                let len = tun.read(buffer)?; 
                Ok(len)
            }
        }
    }

    pub fn write_socket (&mut self, data: &[u8], client_id: Option<u8>) -> Result<()> {
        match self {
            Device::Client { client_socket: socket , server_addr, ..} => {
                let mut bytes_left = data.len(); 
                while bytes_left > 0 {
                    let bytes_written = socket.send_to(data, *server_addr).map_err(|e| SocketSendToError(e.to_string()))?; 
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
                                let bytes_written = socket.send_to(data, *client_addr).map_err(|e| SocketSendToError(e.to_string()))?; 
                                bytes_left = bytes_left - bytes_written;
                            };
                            Ok(())
                        }, 
                        None => {
                            bail!(ClientInfoNotFound)
                        }
                    }
                } else {
                    bail!(ClientInfoGetError)
                }
            }
        }
    }

    pub fn read_socket (&mut self) -> Result<(SocketAddr, Message)> {
        match self {
            Device::Client { client_socket: socket , ..} | Device::Server { server_socket : socket, .. } => {
                let mut buffer = [0; 2000];
                let (len, from_addr) = socket.recv_from(&mut buffer).map_err(|e| SocketReadError(e.to_string()))?;
                let msg = serde_json::from_slice::<Message>(&buffer[..len]).map_err(|e| DeserialError(e.to_string()))?;
                Ok((from_addr, msg))
            },
        } 
    }

    // Initiates the handshake by calculating the client public key using Diffie Hellman algorithm and send the request with the public key to the server
    pub fn initiate_handshake (&self) -> Result<()> {
        match self {
            Device::Client {
                client_socket,
                server_addr,
                private_key,
                ..
            } => {
                let client_public_key = generate_public_key(private_key);

                let request_msg = Message::Request { client_public_key }; //create a request message

                let serialized = serde_json::to_string::<Message>(&request_msg).map_err(|e| SerialError(e.to_string()))?; //serialize the message to json

                client_socket.send_to(serialized.as_bytes(), *server_addr).map_err(|e| SocketSendToError(e.to_string()))?;

                println!("request sent to the server {}", server_addr);

                Ok(())
            }
            _ => bail!(IncorrectRecepientError),
        }
    }

    // Processes the response from the server after initiating handshake and calculates shared secret key
    pub fn process_response (&self, response_msg: Message) -> Result<BigInt> {
        match self {
            Device::Client {private_key, tun,..} => {
                match response_msg {
                    Message::Response { client_id, server_public_key,  } => {
                        tun.up(Some(client_id));
                        let shared_secret_key = generate_shared_key(&server_public_key, private_key);
                        Ok(shared_secret_key)
                    }, 
                    _ => bail!(IncorrectMessageError)
                }
            }, 
            _ => bail!(IncorrectRecepientError)
        }
    }

    // Processes the request from the client after initiating handshake, sends the response and calculates shared secret key
    pub fn process_request (&mut self, client_addr: &SocketAddr, request_msg: Message) -> Result<(u8, BigInt)> {
        match self {
            Device::Server {server_socket, private_key, available_ids,..} => {
                match request_msg {
                    Message::Request { client_public_key } => {
                        let server_public_key = generate_public_key(private_key); 
                        match available_ids.pop() {
                            Some(client_id) => {
                                let response_msg = Message::Response { client_id, server_public_key };
                                let serialized = serde_json::to_string::<Message>(&response_msg).map_err(|e| SerialError(e.to_string()))?;
                                
                                server_socket.send_to(serialized.as_bytes(), client_addr.clone()).map_err(|e| SocketSendToError(e.to_string()))?;
                                
                                println!("Response sent to the client {}", client_addr);
                                
                                let shared_secret_key = generate_shared_key(&client_public_key, private_key);

                                Ok((client_id, shared_secret_key))
                            }, 
                            None => {
                                bail!(ServerPortError)
                            }
                        }
                    },
                    _ => bail!(IncorrectMessageError)
                }
            }, 
            _ => bail!(IncorrectRecepientError)
        }
    }

    pub fn setup_default_gateway(&mut self) {
        match self {
            Device::Client { server_addr , default_gateway, ..} => {
                *default_gateway = if cfg!(target_os = "macos") {
                    let default_gw_output = process::Command::new("route").arg("-n").arg("get").arg("default").output().unwrap();
                    assert!(default_gw_output.status.success());
                    let stdout = String::from_utf8(default_gw_output.stdout).unwrap();
                    let gateway = stdout
                        .lines()
                        .find(|line| line.contains("gateway"))
                        .map(|line| line.split_whitespace().nth(1).unwrap_or(""))
                        .unwrap();
                    // Set the default gateway to Tun device's remote address
                    assert!(process::Command::new("route").arg("add").arg(server_addr.ip().to_string()).arg(gateway).status().unwrap().success()); 
                    assert!(process::Command::new("route").arg("delete").arg("default").status().unwrap().success()); 
                    assert!(process::Command::new("route").arg("add").arg("default").arg("10.20.20.1").status().unwrap().success()); 
                    Some(gateway.to_string())
                } else if cfg!(target_os = "linux") {
                    let default_gw_output = process::Command::new("ip").arg("route").arg("show").arg("default").output().unwrap(); 
                    assert!(default_gw_output.status.success()); 
                    let mut words = str::from_utf8(&default_gw_output.stdout).unwrap().split_whitespace();
                    let mut interface = None;
                    let mut gateway = None;
        
                    while let Some(word) = words.next() {
                        match word {
                            "dev" => interface = words.next(),
                            "via" => gateway = words.next(),
                            _ => {}
                        }
                    }
                    assert!(process::Command::new("ip").arg("route").arg("add").arg(server_addr.ip().to_string()).arg("via").arg(gateway.unwrap()).status().unwrap().success()); 
                    assert!(process::Command::new("ip").arg("route").arg("del").arg("default").arg("via").arg(gateway.unwrap()).status().unwrap().success()); 
                    assert!(process::Command::new("ip").arg("route").arg("add").arg("default").arg("via").arg("10.20.20.1").arg("dev").arg(interface.unwrap()).status().unwrap().success());
                    Some(gateway.unwrap().to_string())
                } else {
                    unimplemented!();
                }
            }, 
            _ => ()
        }
    }

    pub fn return_default_gateway(&self) {
        match self {
            Device::Client { default_gateway, ..} => {
                if let Some(gw) = default_gateway {
                    assert!(process::Command::new("route").arg("delete").arg("default").status().unwrap().success()); 
                    assert!(process::Command::new("route").arg("add").arg("default").arg(gw).status().unwrap().success());
                }
            }, 
            _ => ()
        }
    }
}