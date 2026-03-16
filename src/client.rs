use std::{
    io::{Read, Write},
    net::SocketAddr,
    os::fd::AsRawFd,
};

use anyhow::{bail, Result};
use mio::{net::UdpSocket, unix::SourceFd, Events, Interest, Poll, Token};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

use crate::{
    comm::Message,
    crypto::{decrypt_data, encrypt_data, generate_public_key, generate_shared_key},
    error::{ClientError, CommError, LogicError, SocketError},
    tun::{config::Configuration, TunDevice},
};

pub struct Client {
    socket: UdpSocket,
    server_addr: SocketAddr,
    tun: TunDevice,
    shared_secret_key: Option<BigUint>,
    private_key: BigUint,
}

impl Client {
    pub fn init(port: u16, server_addr: SocketAddr, tun_config: &Configuration) -> Result<Self> {
        let client_addr = format!("0.0.0.0:{}", port).parse()?;
        let socket = UdpSocket::bind(client_addr)?;
        let private_key = thread_rng().gen_biguint(256);

        let client = Client {
            socket,
            server_addr,
            tun: TunDevice::new(tun_config)?,
            shared_secret_key: None,
            private_key,
        };
        log::info!("Client successfully initialized");
        Ok(client)
    }
    pub fn set_shared_secret_key(&mut self, new_key: BigUint) {
        self.shared_secret_key = Some(new_key);
    }

    pub fn get_shared_secret_key(&self) -> Result<&BigUint> {
        if let Some(shared_key) = self.shared_secret_key.as_ref() {
            Ok(shared_key)
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

        Ok(())
    }

    pub fn process_response(&mut self, response_msg: Message) -> Result<BigUint> {
        if let Message::Response { public_key } = response_msg {
            let shared_secret_key = generate_shared_key(&public_key, &self.private_key);
            Ok(shared_secret_key)
        } else {
            bail!(LogicError::IncorrectMessageError)
        }
    }

    pub fn write_socket(&mut self, data: &[u8]) -> Result<()> {
        let mut bytes_written = 0;
        while bytes_written < data.len() {
            bytes_written += self
                .socket
                .send_to(&data[bytes_written..data.len()], self.server_addr)
                .map_err(|e| SocketError::SocketSendToError(e.to_string()))?;
        }
        log::trace!("[Socket] Written {} bytes", data.len());
        Ok(())
    }

    pub fn read_socket(&mut self) -> Result<(SocketAddr, Message)> {
        let mut buffer = [0; 5000];
        let (len, from_addr) = self
            .socket
            .recv_from(&mut buffer)
            .map_err(|e| SocketError::SocketReadError(e.to_string()))?;
        log::trace!("[Socket] Read {} bytes", len);
        let msg = serde_json::from_slice::<Message>(&buffer[..len])
            .map_err(|e| CommError::DeserialError(e.to_string()))?;

        Ok((from_addr, msg))
    }

    pub fn write_tun(&mut self, data: &[u8]) -> Result<()> {
        let mut bytes_written = 0;
        while bytes_written < data.len() {
            bytes_written += self.tun.write(&data[bytes_written..data.len()])?;
        }

        log::trace!("[Tun] Written {} bytes", bytes_written);

        Ok(())
    }

    pub fn read_tun(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let len = self.tun.read(buffer)?;

        log::trace!("[Tun] Read {} bytes", len);

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
        let mut buffer = [0u8; 2000];

        loop {
            poll.poll(&mut events, None)
                .map_err(|_| CommError::MioPollingError)?; // Replace with async tokio
            for event in &events {
                let start_time = std::time::Instant::now();
                match event.token() {
                    Token(0) => {
                        let socket_start = std::time::Instant::now();
                        match self.read_socket() {
                            Ok((addr, msg)) => {
                                let socket_read_time = socket_start.elapsed();
                                log::trace!("[Socket] Read took {:?}", socket_read_time);

                                if addr != self.server_addr {
                                    continue;
                                }
                                match msg {
                                    Message::Response { .. } => {
                                        let handshake_start = std::time::Instant::now();
                                        let shared_secret_key = self.process_response(msg)?;
                                        log::debug!(
                                            "[Handshake] Shared secret key: {:?}",
                                            shared_secret_key
                                        );
                                        self.set_shared_secret_key(shared_secret_key);
                                        log::trace!(
                                            "[Handshake] Processing took {:?}",
                                            handshake_start.elapsed()
                                        );
                                    }
                                    Message::PayLoad { data } => {
                                        let payload_start = std::time::Instant::now();
                                        log::trace!("[Socket] Payload received");
                                        if let Ok(key) = self.get_shared_secret_key() {
                                            let decrypt_start = std::time::Instant::now();
                                            let decrypted_data = decrypt_data(&data, key)?;
                                            log::trace!(
                                                "[Crypto] Decrypt took {:?}",
                                                decrypt_start.elapsed()
                                            );

                                            let tun_write_start = std::time::Instant::now();
                                            if let Err(e) = self.write_tun(&decrypted_data) {
                                                log::error!("[Socket] Tun write error: {}", e);
                                            }
                                            log::trace!(
                                                "[Tun] Write took {:?}",
                                                tun_write_start.elapsed()
                                            );
                                        } else {
                                            log::error!("[Socket] Connection not yet set between client and server");
                                        }
                                        log::trace!(
                                            "[Socket] Payload processing took {:?}",
                                            payload_start.elapsed()
                                        );
                                    }
                                    _ => (),
                                }
                            }
                            Err(e) => log::error!("[Socket] The read error: {}", e),
                        }
                        log::trace!(
                            "[Socket] Total socket event took {:?}",
                            start_time.elapsed()
                        );
                    }
                    Token(1) => {
                        let tun_start = std::time::Instant::now();
                        match self.read_tun(&mut buffer) {
                            Ok(len) => {
                                let tun_read_time = tun_start.elapsed();
                                log::trace!("[Tun] Read took {:?}", tun_read_time);

                                if len == 0 {
                                    continue;
                                }

                                if len > 1500 {
                                    log::warn!(
                                        "[Tun] Oversized packet received: {} bytes (max 1500)",
                                        len
                                    );
                                    continue;
                                }

                                let data = &buffer[..len];

                                if let Ok(key) = self.get_shared_secret_key() {
                                    log::trace!("[Tun] Payload received");

                                    let encrypt_start = std::time::Instant::now();
                                    let msg = Message::PayLoad {
                                        data: encrypt_data(data, key)?,
                                    };
                                    log::trace!(
                                        "[Crypto] Encrypt took {:?}",
                                        encrypt_start.elapsed()
                                    );

                                    let serialize_start = std::time::Instant::now();
                                    let serialized = serde_json::to_string::<Message>(&msg)
                                        .map_err(|e| CommError::SerialError(e.to_string()))?;
                                    log::trace!(
                                        "[Serialize] JSON took {:?}",
                                        serialize_start.elapsed()
                                    );

                                    let socket_write_start = std::time::Instant::now();
                                    if let Err(e) = self.write_socket(serialized.as_bytes()) {
                                        log::error!("[Tun] Socket write error: {}", e);
                                    }
                                    log::trace!(
                                        "[Socket] Write took {:?}",
                                        socket_write_start.elapsed()
                                    );
                                } else {
                                    log::error!(
                                        "[Tun] Connection not yet set between client and server"
                                    )
                                }
                            }
                            Err(e) => log::error!("[Tun] The read error: {}", e),
                        }
                        log::trace!("[Tun] Total tun event took {:?}", start_time.elapsed());
                    }
                    _ => (),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::client::Client;
    use crate::server::Server;
    use std::net::Ipv4Addr;
    use std::thread;
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_client_data_flow() {
        let _server_addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let _client_addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let payload = [
            0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
            0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
        ];

        let client_ip: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let destination_ip: Ipv4Addr = "142.250.31.100".parse().unwrap();
        let netmask: Ipv4Addr = "255.255.255.255".parse().unwrap();

        let server_thread = thread::spawn(move || {
            let mut server = Server::init(8081, &Configuration::default()).unwrap();
            let mut connection_established = false;

            for _ in 0..10 {
                if let Ok((client_addr, msg)) = server.read_socket() {
                    assert_eq!(client_addr, _client_addr);

                    let shared_secret_key = server.process_request(&client_addr, msg).unwrap();
                    server
                        .set_shared_secret_key(shared_secret_key, client_addr)
                        .unwrap();

                    connection_established = true;
                    break;
                }

                thread::sleep(Duration::from_millis(10));
            }

            assert!(connection_established);

            for _ in 0..10 {
                if let Ok((client_addr, msg)) = server.read_socket() {
                    assert_eq!(client_addr, _client_addr);
                    match msg {
                        Message::PayLoad { data } => {
                            let shared_key = server.get_client_key(&_client_addr).unwrap();

                            let decrypted_data = decrypt_data(&data, shared_key).unwrap();
                            assert!(decrypted_data.len() > payload.len());
                            assert_eq!(
                                decrypted_data[decrypted_data.len() - payload.len()..],
                                payload
                            );
                            break;
                        }
                        _ => panic!(),
                    };
                }

                thread::sleep(Duration::from_millis(10));
            }
        });

        thread::spawn(move || {
            let mut client_dev_config = Configuration::default();
            client_dev_config.address = Some(client_ip);
            client_dev_config.destination = Some(destination_ip);
            client_dev_config.netmask = Some(netmask);

            let mut client = Client::init(8080, _server_addr, &client_dev_config).unwrap();

            client.start().unwrap();
        });

        let packet_source_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));

            let socket = UdpSocket::bind(format!("{}:0", client_ip).parse().unwrap()).unwrap();
            socket
                .connect(format!("{}:8080", destination_ip).parse().unwrap())
                .unwrap();

            socket.send(&payload).unwrap();
        });

        server_thread.join().unwrap();
        packet_source_thread.join().unwrap();
    }
}
