use std::{io::{Read, Write}, net::SocketAddr, os::fd::AsRawFd};

use anyhow::{bail, Result};
use mio::{net::UdpSocket, unix::SourceFd, Events, Interest, Poll, Token};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

use crate::{comm::{Message, SecretData}, crypto::{decrypt_data, encrypt_data, generate_public_key, generate_shared_key}, error::{ClientError, CommError, LogicError, SocketError}, tun::{config::Configuration, TunDevice}};


pub struct Client {
    socket: UdpSocket,
    server_addr: SocketAddr,
    tun: TunDevice,
    shared_secret_key: Option<BigUint>,
    private_key: BigUint,
    id: Option<u8>,
}

impl Client {
    pub fn init(port: u16, server_addr: SocketAddr) -> Result<Self> {
        let client_addr = format!("127.0.0.1:{}", port).parse()?;
        let socket = UdpSocket::bind(client_addr)?;
        let private_key = thread_rng().gen_biguint(256); 

        let client = Client {
            socket,
            server_addr,
            tun: TunDevice::new(&Configuration::default())?,
            shared_secret_key: None,
            private_key,
            id: None,
        };

        Ok(client)
    }
    pub fn set_shared_secret_key(
        &mut self,
        new_key: BigUint,
    ) {
        self.shared_secret_key = Some(new_key);
    }

    pub fn get_shared_secret_key(&self) -> Result<SecretData> {
        if let Some(shared_key) = self.shared_secret_key.as_ref() {
            Ok(SecretData::SharedSecretKey(shared_key))
        } else {
            bail!(ClientError::SharedKeyGetError)
        }
    }

    pub fn initiate_handshake(&self) -> Result<()> {
        let public_key = generate_public_key(&self.private_key);

        let request_msg = Message::Request { public_key };

        let serialized = serde_json::to_string::<Message>(&request_msg)
            .map_err(|e| CommError::SerialError(e.to_string()))?;

        self.socket
            .send_to(serialized.as_bytes(), self.server_addr)
            .map_err(|e| SocketError::SocketSendToError(e.to_string()))?;

        println!("request sent to the server {}", self.server_addr);

        Ok(())
    }

    pub fn process_response(&mut self, response_msg: Message) -> Result<BigUint> {
        if let Message::Response { client_id, public_key } = response_msg {
            self.id = Some(client_id); 
            let shared_secret_key = generate_shared_key(&public_key, &self.private_key); 
            Ok(shared_secret_key)
        } else {
            bail!(LogicError::IncorrectMessageError)
        }
    }

    pub fn write_socket(&mut self, data: &[u8]) -> Result<()> {
        let mut bytes_written = 0;
        while bytes_written < data.len() {
            bytes_written += self.socket
                .send_to(&data[bytes_written..data.len()], self.server_addr)
                .map_err(|e| SocketError::SocketSendToError(e.to_string()))?;
        }
        Ok(())
    }

    pub fn read_socket(&mut self) -> Result<(SocketAddr, Message)> {
        let mut buffer = [0; 2000];
        let (len, from_addr) = self.socket
            .recv_from(&mut buffer)
            .map_err(|e| SocketError::SocketReadError(e.to_string()))?;
        let msg = serde_json::from_slice::<Message>(&buffer[..len])
            .map_err(|e| CommError::DeserialError(e.to_string()))?;
        Ok((from_addr, msg))
    }

    pub fn write_tun(&mut self, data: Vec<u8>) -> Result<()> {
        let mut bytes_written = 0;
        while bytes_written < data.len() {
            bytes_written += self.tun.write(&data[bytes_written..data.len()])?; 
        }

        Ok(())
    }

    pub fn read_tun(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let len = self.tun.read(buffer)?;
        Ok(len)
    }

    pub fn start(&mut self) -> Result<()> {
        let mut poll = Poll::new()?;
        let mut events = Events::with_capacity(1024);

        let tun_raw_fd = self.tun.as_raw_fd();
        let mut tun_socket = SourceFd(&tun_raw_fd); 

        poll.registry()
            .register(&mut self.socket, Token(0), Interest::READABLE)
            .map_err(|_| CommError::MioRegistryError)?;
        poll.registry()
            .register(
                &mut tun_socket,
                Token(1),
                Interest::READABLE | Interest::WRITABLE,
            )
            .map_err(|_| CommError::MioRegistryError)?;

        self.initiate_handshake()?;

        loop {
            poll.poll(&mut events, None).map_err(|_| CommError::MioPollingError)?; // Replace with async tokio
            for event in &events {
                match event.token() {
                    Token(0) => {
                        match self.read_socket() {
                            Ok((addr, msg)) => {
                                if addr != self.server_addr {
                                    continue; 
                                }
                                match msg {
                                    Message::Response { .. } => {
                                        let shared_secret_key = self.process_response(msg)?;
                                        println!("Shared secret key is {}", shared_secret_key);
                                        self.set_shared_secret_key(shared_secret_key);
                                    }
                                    Message::PayLoad { client_id: _, data } => {
                                        let shared_secret = self
                                            .get_shared_secret_key()
                                            .map_err(|e| println!("Error: {:?}", e));
                                        if let Ok(SecretData::SharedSecretKey(key)) = shared_secret {
                                            let decrypted_data = decrypt_data(&data, key)?;
                                            println!("IP packet received: {:?}", decrypted_data);
                                            self.write_tun(decrypted_data)?;
                                        }
                                    }
                                    _ => (),
                                }
                            }
                            Err(e) => eprintln!("The error: {}", e),
                        }
                    }
                    Token(1) => {
                        let mut buffer = [0u8; 2000];
                        match self.read_tun(&mut buffer) {
                            Ok(len) => {
                                if len == 0 {
                                    continue; 
                                }
                                let data = &buffer[..len];
                                match self.id {
                                    Some(id) => {
                                        let shared_secret = self
                                            .get_shared_secret_key()
                                            .map_err(|e| println!("Error: {:?}", e));
                                        if let Ok(SecretData::SharedSecretKey(key)) = shared_secret
                                        {
                                            let encrypted_data = encrypt_data(data, key)?;
                                            let msg = Message::PayLoad {
                                                client_id: id,
                                                data: encrypted_data,
                                            };
                                            let serialized = serde_json::to_string::<Message>(&msg)
                                                .map_err(|e| CommError::SerialError(e.to_string()))?;

                                            if let Err(e) = self.write_socket(serialized.as_bytes()) {
                                                eprintln!("Error: {}", e.to_string()); 
                                            }
                                        }
                                    }
                                    None => {
                                        eprintln!(
                                            "Connection not yet set between client and server"
                                        )
                                    }
                                }
                            }
                            Err(e) => eprintln!("The error: {}", e),
                        };
                    }
                    _ => (),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    
}
