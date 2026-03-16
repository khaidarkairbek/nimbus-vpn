use std::{
    collections::HashMap,
    io::{Read, Write},
    net::SocketAddr,
    os::fd::AsRawFd,
    process,
};

use anyhow::{bail, Result};
use mio::{net::UdpSocket, unix::SourceFd, Events, Interest, Poll, Token};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

use crate::{
    comm::Message,
    crypto::{decrypt_data, encrypt_data, generate_public_key, generate_shared_key},
    error::{CommError, LogicError, SocketError},
    tun::{config::Configuration, TunDevice},
};

pub struct Server {
    socket: UdpSocket,
    clients: HashMap<SocketAddr, BigUint>,
    tun: TunDevice,
    private_key: BigUint,
}

impl Server {
    pub fn init(port: u16, tun_config: &Configuration) -> Result<Self> {
        let server_addr = format!("0.0.0.0:{}", port).parse()?;
        let socket = UdpSocket::bind(server_addr)?;
        let private_key = thread_rng().gen_biguint(256);

        Server::enable_ip_forwarding()?;

        let server = Server {
            socket,
            clients: HashMap::new(),
            tun: TunDevice::new(tun_config)?,
            private_key,
        };

        log::info!("Server successfully initialized.");

        Ok(server)
    }

    pub fn set_shared_secret_key(
        &mut self,
        new_key: BigUint,
        client_addr: SocketAddr,
    ) -> Result<()> {
        self.clients.insert(client_addr, new_key);
        Ok(())
    }

    #[cfg(test)]
    pub fn get_client_key(&self, addr: &SocketAddr) -> Option<&BigUint> {
        self.clients.get(addr)
    }

    pub fn process_request(
        &mut self,
        client_addr: &SocketAddr,
        request_msg: Message,
    ) -> Result<BigUint> {
        if let Message::Request {
            public_key: client_public_key,
        } = request_msg
        {
            let public_key = generate_public_key(&self.private_key);
            let response_msg = Message::Response { public_key };
            let serialized = serde_json::to_string::<Message>(&response_msg)
                .map_err(|e| CommError::SerialError(e.to_string()))?;

            self.socket
                .send_to(serialized.as_bytes(), *client_addr)
                .map_err(|e| SocketError::SocketSendToError(e.to_string()))?;

            let shared_secret_key = generate_shared_key(&client_public_key, &self.private_key);

            Ok(shared_secret_key)
        } else {
            bail!(LogicError::IncorrectMessageError)
        }
    }

    pub fn write_socket(&self, data: &[u8], client_addr: &SocketAddr) -> Result<()> {
        let mut bytes_written = 0;
        while bytes_written < data.len() {
            bytes_written += self
                .socket
                .send_to(&data[bytes_written..data.len()], *client_addr)
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

    fn write_tun(&mut self, data: &[u8]) -> Result<()> {
        let mut bytes_written = 0;

        while bytes_written < data.len() {
            bytes_written += self.tun.write(&data[bytes_written..data.len()])?;
        }

        log::trace!("[Tun] Written {} bytes", bytes_written);

        Ok(())
    }

    fn read_tun(&mut self, buffer: &mut [u8]) -> Result<usize> {
        let len = self.tun.read(buffer)?;

        log::trace!("[Tun] Read {} bytes", len);

        Ok(len)
    }

    fn enable_ip_forwarding() -> Result<()> {
        if cfg!(target_os = "macos") {
            // MacOS: sysctl -w net.inet.ip.forwarding=1
            let status = process::Command::new("sysctl")
                .arg("-w")
                .arg("net.inet.ip.forwarding=1")
                .status()?;

            if !status.success() {
                bail!("sysctl failed to enable IP forwarding on macOS (exit code: {:?})", status.code());
            }
        } else if cfg!(target_os = "linux") {
            // Linux: sysctl -w net.ipv4.ip_forward=1
            let status = process::Command::new("sysctl")
                .arg("-w")
                .arg("net.ipv4.ip_forward=1")
                .status()?;

            if !status.success() {
                bail!("sysctl failed to enable IP forwarding on Linux (exit code: {:?})", status.code());
            }
        } else {
            bail!("IP forwarding is not supported on this platform");
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
            poll.poll(&mut events, None)
                .map_err(|_| CommError::MioPollingError)?;
            for event in &events {
                let start_time = std::time::Instant::now();
                match event.token() {
                    Token(0) => {
                        let socket_start = std::time::Instant::now();
                        match self.read_socket() {
                            Ok((client_addr, msg)) => {
                                let socket_read_time = socket_start.elapsed();
                                log::trace!("[Socket] Read took {:?}", socket_read_time);

                                match msg {
                                    Message::Request { .. } => {
                                        let handshake_start = std::time::Instant::now();
                                        let shared_secret_key =
                                            self.process_request(&client_addr, msg)?;
                                        log::debug!(
                                            "[Handshake] Shared secret key: {:?}",
                                            shared_secret_key
                                        );
                                        self.set_shared_secret_key(shared_secret_key, client_addr)?;
                                        log::trace!(
                                            "[Handshake] Processing took {:?}",
                                            handshake_start.elapsed()
                                        );
                                    }
                                    Message::PayLoad { data } => {
                                        let payload_start = std::time::Instant::now();
                                        log::trace!("[Socket] Payload received");

                                        let key = self.clients.get(&client_addr).cloned();
                                        if let Some(key) = key {
                                            let decrypt_start = std::time::Instant::now();
                                            let decrypted_data = decrypt_data(&data, &key)?;
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
                                            log::warn!(
                                                "[Socket] Payload from unregistered client: {}",
                                                client_addr
                                            );
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

                                let clients: Vec<(SocketAddr, BigUint)> = self
                                    .clients
                                    .iter()
                                    .map(|(&addr, key)| (addr, key.clone()))
                                    .collect();

                                if clients.is_empty() {
                                    log::warn!("[Tun] No connected clients to forward packet to");
                                }

                                for (client_addr, key) in &clients {
                                    log::trace!("[Tun] Forwarding packet to {}", client_addr);

                                    let encrypt_start = std::time::Instant::now();
                                    let encrypted_data = match encrypt_data(data, key) {
                                        Ok(d) => d,
                                        Err(e) => {
                                            log::error!(
                                                "[Crypto] Encrypt error for {}: {}",
                                                client_addr,
                                                e
                                            );
                                            continue;
                                        }
                                    };
                                    log::trace!(
                                        "[Crypto] Encrypt took {:?}",
                                        encrypt_start.elapsed()
                                    );

                                    let serialize_start = std::time::Instant::now();
                                    let msg = Message::PayLoad {
                                        data: encrypted_data,
                                    };
                                    let serialized = match serde_json::to_string::<Message>(&msg) {
                                        Ok(s) => s,
                                        Err(e) => {
                                            log::error!(
                                                "[Serialize] Error for {}: {}",
                                                client_addr,
                                                e
                                            );
                                            continue;
                                        }
                                    };
                                    log::trace!(
                                        "[Serialize] JSON took {:?}",
                                        serialize_start.elapsed()
                                    );

                                    let socket_write_start = std::time::Instant::now();
                                    if let Err(e) =
                                        self.write_socket(serialized.as_bytes(), client_addr)
                                    {
                                        log::error!(
                                            "[Tun] Socket write error for {}: {}",
                                            client_addr,
                                            e
                                        );
                                    }
                                    log::trace!(
                                        "[Socket] Write took {:?}",
                                        socket_write_start.elapsed()
                                    );
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
