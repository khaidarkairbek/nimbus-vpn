use std::{collections::HashMap, io::{Read, Write}, net::SocketAddr, os::fd::AsRawFd, process, time::Duration};

use anyhow::{bail, Result};
use mio::{net::UdpSocket, unix::SourceFd, Events, Interest, Poll, Token};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

use crate::{
    comm::Message,
    crypto::{decrypt_data, encrypt_data, generate_public_key, generate_shared_key},
    error::{CommError, LogicError, ServerError, SocketError},
    tun::{config::Configuration, TunDevice},
};

pub struct Server {
    socket: UdpSocket,
    client_key_map: HashMap<u8, (SocketAddr, BigUint)>,
    tun: TunDevice,
    private_key: BigUint,
    available_ids: Vec<u8>,
}

impl Server {
    pub fn init(port: u16, tun_config: &Configuration) -> Result<Self> {
        let server_addr = format!("127.0.0.1:{}", port).parse()?;
        let socket = UdpSocket::bind(server_addr)?;
        let private_key = thread_rng().gen_biguint(256);

        //Server::enable_ip_forwarding()?;

        let server = Server {
            socket,
            client_key_map: HashMap::new(),
            tun: TunDevice::new(tun_config)?,
            private_key,
            available_ids: (2..101).collect(),
        };

        Ok(server)
    }

    pub fn set_shared_secret_key(
        &mut self,
        new_key: BigUint,
        client_info: Option<(u8, SocketAddr)>,
    ) -> Result<()> {
        if let Some((id, addr)) = client_info {
            self.client_key_map.insert(id, (addr, new_key));
            Ok(())
        } else {
            bail!(ServerError::ClientInfoSetError)
        }
    }

    pub fn get_shared_secret_key(&self, client_id: u8) -> Result<(&SocketAddr, &BigUint)> {
        match self.client_key_map.get(&client_id) {
            None => bail!(ServerError::ClientInfoGetError),
            Some((client_addr, shared_key)) => {
                Ok((client_addr, shared_key))
            }
        }
    }

    pub fn process_request(
        &mut self,
        client_addr: &SocketAddr,
        request_msg: Message,
    ) -> Result<(u8, BigUint)> {
        if let Message::Request { public_key: client_public_key } = request_msg {
            let public_key = generate_public_key(&self.private_key);
            match self.available_ids.pop() {
                Some(client_id) => {
                    let response_msg = Message::Response {
                        client_id,
                        public_key,
                    };
                    let serialized = serde_json::to_string::<Message>(&response_msg)
                        .map_err(|e| CommError::SerialError(e.to_string()))?;

                    self.socket
                        .send_to(serialized.as_bytes(), client_addr.clone())
                        .map_err(|e| SocketError::SocketSendToError(e.to_string()))?;

                    let shared_secret_key =
                        generate_shared_key(&client_public_key, &self.private_key);

                    Ok((client_id, shared_secret_key))
                }
                None => {
                    bail!(ServerError::ServerPortError)
                }
            }
        } else {
            bail!(LogicError::IncorrectMessageError)
        }
    }

    pub fn write_socket(&mut self, data: &[u8], client_id: u8) -> Result<()> {
        match self.client_key_map.get(&client_id) {
            Some((client_addr, _)) => {
                let mut bytes_written = 0;
                while bytes_written < data.len() {
                    bytes_written += self
                        .socket
                        .send_to(&data[bytes_written..data.len()], *client_addr)
                        .map_err(|e| SocketError::SocketSendToError(e.to_string()))?;
                }
                Ok(())
            }
            None => {
                bail!(ServerError::ClientInfoNotFound)
            }
        }
    }

    pub fn read_socket(&mut self) -> Result<(SocketAddr, Message)> {
        let mut buffer = [0; 2000];
        let (len, from_addr) = self
            .socket
            .recv_from(&mut buffer)
            .map_err(|e| SocketError::SocketReadError(e.to_string()))?;
        let msg = serde_json::from_slice::<Message>(&buffer[..len])
            .map_err(|e| CommError::DeserialError(e.to_string()))?;
        Ok((from_addr, msg))
    }

    fn write_tun(&mut self, data: Vec<u8>) -> Result<()> {
        let mut bytes_written = 0;

        while bytes_written < data.len() {
            bytes_written += self.tun.write(&data[bytes_written..data.len()])?;
        }

        Ok(())
    }

    fn read_tun(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let len = self.tun.read(buffer)?;
        Ok(len)
    }

    #[expect(unused)]
    fn enable_ip_forwarding() -> Result<()> {
        if cfg!(target_os = "macos") {
            // MacOS: sysctl -w net.inet.ip.forwarding=1
            let status = process::Command::new("sysctl")
                .arg("-w")
                .arg("net.net.ip.forwarding=1")
                .status()?;

            assert!(status.success());
        } else if cfg!(target_os = "linux") {
            // Linux: sysctl -w net.ipv4.ip_forward=1
            let status = process::Command::new("sysctl")
                .arg("-w")
                .arg("net.ipv4.ip_forward=1")
                .status()?;
            assert!(status.success());
        } else {
            unimplemented!()
        }
        Ok(())
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

        let mut buffer = [0u8; 2000];

        loop {
            poll.poll(&mut events, Some(Duration::from_millis(100)))
                .map_err(|_| CommError::MioPollingError)?;
            for event in &events {
                match event.token() {
                    Token(0) => match self.read_socket() {
                        Ok((client_addr, msg)) => match msg {
                            Message::Request { .. } => {
                                let (client_id, shared_secret_key) = self.process_request(&client_addr, msg)?;
                                self.set_shared_secret_key(
                                    shared_secret_key,
                                    Some((client_id, client_addr)),
                                )?;
                            }
                            Message::PayLoad { client_id, data } => {
                                let shared_secret = self.get_shared_secret_key(client_id);
                                if let Ok((_, key)) = shared_secret
                                {
                                    let decrypted_data = decrypt_data(&data, key)?;
                                    self.write_tun(decrypted_data)?;
                                } else {
                                    eprintln!(
                                        "Connection not yet set between client and server"
                                    )
                                }
                            }
                            _ => (),
                        },
                        Err(e) => eprintln!("The error: {}", e),
                    },
                    Token(1) => {
                        match self.read_tun(&mut buffer) {
                            Ok(len) => {
                                if len == 0 {
                                    continue; 
                                }

                                let data = &buffer[..len];
                                let client_internal_tun_address = &data[16..=19];
                                let client_id = client_internal_tun_address[3];
                                let shared_secret = self.get_shared_secret_key(client_id);

                                if let Ok((_, key)) = shared_secret
                                {
                                    let encrypted_data = encrypt_data(data, key)?;
                                    let msg = Message::PayLoad {
                                        client_id: client_id,
                                        data: encrypted_data,
                                    };
                                    let serialized = serde_json::to_string::<Message>(&msg)
                                        .map_err(|e| CommError::SerialError(e.to_string()))?;
                                    if let Err(e) = self.write_socket(serialized.as_bytes(), client_id)
                                    {
                                        eprintln!("Error: {}", e.to_string());
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
