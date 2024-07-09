use chacha20poly1305::aead::generic_array::GenericArray;
use mio::net::UdpSocket;
use crate::tun::TunDevice;
use std::result;
use std::{collections::HashMap, net::SocketAddr};
use serde::{Deserialize, Serialize};
use serde_json;
use num_bigint::BigInt;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, ChaChaPoly1305, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit, NewAead, Nonce, OsRng};
use std::convert::TryInto; //for conversions

// Diffie Hellman Key Exchange implementation
const DH_MODULUS: &'static str = "23";  // Placeholder values for testing
const DH_BASE: &'static str = "5";

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


fn pad_key_to_32_bytes(key: &[u8]) -> [u8; 32] {
    let mut padded_key_bytes = [0u8; 32]; //array of 32 bytes zeros
    let length = std::cmp::min(key.len(), 32); 
    padded_key_bytes[..length].copy_from_slice(&key[..length]); //copy key bytes to the padded arr
    padded_key_bytes
}


pub fn encrypt_data(data: &[u8], key: &BigInt) -> Result<Vec<u8>, String>{
    let key_in_bytes== key.to_bytes_le(); //bigint key to a byte arr
    let key_bytes_pad = pad_key_to_32_bytes(&key_in_bytes); //pad key to 32 bytes
    let cipher = ChaChaPoly1305::new(GenericArray::from_slice(&key_bytes_pad)); //create chacha instance with the padded key
    let nonce = ChaChaPoly1305::generate_nonce(&mut OsRng); //generate random nonce
    let cipher_text = cipher.encrypt(&nonce, data).map_err(|e| e.to_string())?; //encrypt the data with generated nonce
    let mut result = nonce.to_vec(); //combine the nonce and ciphertext into a single vector
    result.extend(cipher_text);
    Ok(result) 
    
}

pub fn decrypt_data(cipher_text: &[u8], key: &BigInt) -> Result<Vec<u8>, String>{
    let key_in_bytes= key.to_bytes_le(); //bigint key to a byte arr
    let key_bytes_pad = pad_key_to_32_bytes(&key_in_bytes); //pad key to 32 bytes
    let cipher = ChaChaPoly1305::new(GenericArray::from_slice(&key_bytes_pad)); //create chacha instance with the padded key
    let (nonce, cipher_text) = cipher_text.split_at(12); //split the cipher text into nonce and actual ciphertext
    let nonce = GenericArray::from_slice(nonce); 
    let plain_text = cipher.decrypt(nonce, cipher_text).map_err(|e| e.to_string())?; //decrypt the ciphertext w the nonce 
    Ok(plain_text)
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
}


use aes_gcm::Aes256Gcm; // Or any other cryptographic algorithm
use aes_gcm::aead::{Aead, KeyInit, OsRng, NewAead};
use aes_gcm::aead::generic_array::GenericArray;
use num_bigint::BigInt;
use std::convert::TryInto;

// Encrypt data
pub fn encrypt_data(data: &[u8], key: &BigInt) -> Result<Vec<u8>, String> {
    let key_bytes = key.to_bytes_le();
    let key_bytes_padded = pad_key_to_32_bytes(&key_bytes);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_bytes_padded));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // Generate a random nonce
    let ciphertext = cipher.encrypt(&nonce, data).map_err(|e| e.to_string())?;
    let mut result = nonce.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

// Decrypt data
pub fn decrypt_data(ciphertext: &[u8], key: &BigInt) -> Result<Vec<u8>, String> {
    let key_bytes = key.to_bytes_le();
    let key_bytes_padded = pad_key_to_32_bytes(&key_bytes);
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key_bytes_padded));
    let (nonce, ciphertext) = ciphertext.split_at(12); // Extract the nonce
    let nonce = GenericArray::from_slice(nonce);
    let plaintext = cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())?;
    Ok(plaintext)
}

// Helper function to pad the key to 32 bytes
fn pad_key_to_32_bytes(key: &[u8]) -> [u8; 32] {
    let mut key_bytes_padded = [0u8; 32];
    let len = std::cmp::min(key.len(), 32);
    key_bytes_padded[..len].copy_from_slice(&key[..len]);
    key_bytes_padded
}
