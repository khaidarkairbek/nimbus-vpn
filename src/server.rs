use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr},
    os::fd::AsRawFd,
    process,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Result};
use mio::{net::UdpSocket, unix::SourceFd, Events, Interest, Poll, Token};
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use wincode; 

use crate::{
    comm::Message,
    crypto::{decrypt_data, encrypt_data, generate_public_key, generate_shared_key},
    error::{CommError, LogicError, SocketError, TunOperationError},
    tun::{config::Configuration, TunDevice},
};

pub struct Server {
    socket: UdpSocket,
    clients: HashMap<SocketAddr, BigUint>,
    client_ips: HashMap<Ipv4Addr, SocketAddr>,
    tun: TunDevice,
    private_key: BigUint,
}

fn ipv4_src(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() >= 20 && (packet[0] >> 4) == 4 {
        Some(Ipv4Addr::from([packet[12], packet[13], packet[14], packet[15]]))
    } else {
        None
    }
}

fn ipv4_dst(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() >= 20 && (packet[0] >> 4) == 4 {
        Some(Ipv4Addr::from([packet[16], packet[17], packet[18], packet[19]]))
    } else {
        None
    }
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
            client_ips: HashMap::new(),
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
    ) {
        self.clients.insert(client_addr, new_key);
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
            let response_msg = Message::Response { public_key: public_key.to_bytes_be() };
            let serialized = wincode::serialize(&response_msg)
                .map_err(|e| CommError::SerialError(e.to_string()))?;

            self.socket
                .send_to(&serialized, *client_addr)
                .map_err(|e| SocketError::SocketSendToError(e.to_string()))?;

            let client_public_key = BigUint::from_bytes_be(&client_public_key);
            let shared_secret_key = generate_shared_key(&client_public_key, &self.private_key);

            Ok(shared_secret_key)
        } else {
            bail!(LogicError::IncorrectMessageError)
        }
    }

    pub fn write_socket(&self, data: &[u8], client_addr: &SocketAddr) -> Result<(), SocketError> {
        let bytes_written = self
            .socket
            .send_to(data, *client_addr)
            .map_err(|e| SocketError::SocketSendToError(e.to_string()))?; 

        if bytes_written < data.len() {
            return Err(SocketError::SocketSendToError("bytes_written less than buffer len to write".to_string()));
        }

        log::trace!("[Socket] Written {} bytes", data.len());
        Ok(())
    }

    pub fn read_socket(&mut self, buffer: &mut [u8]) -> Result<(SocketAddr, Message)> {
        let (len, from_addr) = self
            .socket
            .recv_from(buffer)
            .map_err(|e| SocketError::SocketReadError(e.to_string()))?;
        log::trace!("[Socket] Read {} bytes", len);
        let msg: Message = wincode::deserialize(&buffer[..len])
            .map_err(|e| CommError::DeserialError(e.to_string()))?; 
        Ok((from_addr, msg))
    }

    fn write_tun(&mut self, data: &[u8]) -> Result<(), TunOperationError> {

        let bytes_written = self
            .tun
            .write(data)
            .map_err(|e| TunOperationError::TunWriteError(e.to_string()))?; 
        
        if bytes_written < data.len() {
            return Err(TunOperationError::TunWriteError("bytes_written less than buffer len to write".to_string()));
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

    pub fn start(&mut self, stop: Arc<AtomicBool>) -> Result<()> {
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
                Interest::READABLE,
            )
            .map_err(|_| CommError::MioRegistryError)?;

        let mut buffer = [0u8; 2000];
        let mut socket_buffer = [0u8; 8192]; 

        loop {
            if stop.load(Ordering::Relaxed) {
                break Ok(());
            }

            poll.poll(&mut events, Some(Duration::from_millis(100)))
                .map_err(|_| CommError::MioPollingError)?;
            for event in &events {
                let start_time = std::time::Instant::now();
                match event.token() {
                    Token(0) => {
                        let socket_start = std::time::Instant::now();
                        match self.read_socket(&mut socket_buffer) {
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
                                        self.set_shared_secret_key(shared_secret_key, client_addr);
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

                                            if let Some(src_ip) = ipv4_src(&decrypted_data) {
                                                self.client_ips.insert(src_ip, client_addr);
                                            }

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

                                let dst_ip = match ipv4_dst(data) {
                                    Some(ip) => ip,
                                    None => {
                                        log::warn!("[Tun] Could not parse destination IP, dropping packet");
                                        continue;
                                    }
                                };

                                let client_addr = match self.client_ips.get(&dst_ip).copied() {
                                    Some(addr) => addr,
                                    None => {
                                        log::warn!("[Tun] No client for destination {}, dropping packet", dst_ip);
                                        continue;
                                    }
                                };

                                let key = match self.clients.get(&client_addr).cloned() {
                                    Some(k) => k,
                                    None => {
                                        log::warn!("[Tun] No key for client {}", client_addr);
                                        continue;
                                    }
                                };

                                log::trace!("[Tun] Forwarding packet to {}", client_addr);

                                let encrypt_start = std::time::Instant::now();
                                let encrypted_data = match encrypt_data(data, &key) {
                                    Ok(d) => d,
                                    Err(e) => {
                                        log::error!("[Crypto] Encrypt error for {}: {}", client_addr, e);
                                        continue;
                                    }
                                };
                                log::trace!("[Crypto] Encrypt took {:?}", encrypt_start.elapsed());

                                let serialize_start = std::time::Instant::now();
                                let msg = Message::PayLoad { data: encrypted_data };
                                let serialized = match wincode::serialize(&msg) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        log::error!("[Serialize] Error for {}: {}", client_addr, e);
                                        continue;
                                    }
                                };
                                log::trace!("[Serialize] Binary took {:?}", serialize_start.elapsed());

                                let socket_write_start = std::time::Instant::now();
                                if let Err(e) = self.write_socket(&serialized, &client_addr) {
                                    log::error!("[Tun] Socket write error for {}: {}", client_addr, e);
                                }
                                log::trace!("[Socket] Write took {:?}", socket_write_start.elapsed());
                            }
                            Err(e) => log::error!("[Tun] The read error: {}", e),
                        }
                        log::trace!("[Tun] Total tun event took {:?}", start_time.elapsed());
                        poll.registry()
                            .reregister(&mut tun_socket, Token(1), Interest::READABLE)
                            .map_err(|_| CommError::MioRegistryError)?;
                    }
                    _ => (),
                }
            }
        }
    }
}
