use mio::{net::UdpSocket, unix::SourceFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{net::SocketAddr, collections::HashMap, os::fd::AsRawFd, process, str};
use num_bigint::BigInt;
use mio::{Events, Poll as Mio_Poll, Interest, Token};
use crate::dev::{Device, Message, SecretData};
use crate::tun::TunDevice;
use anyhow::Result;
use crate::error::{
    ClientError, CommError::*, ServerError, SocketError::*
};
use ctrlc; 

pub fn server_side (server_addr : SocketAddr, tun_num : Option<u8>, server_private_key : BigInt) -> Result<()> {   
    let mut server_socket = UdpSocket::bind(server_addr).map_err(|e| SocketBindError(e.to_string()))?;

    // Enable ipv4 forwarding command: 
    // Linux: sysctl -w net.ipv4.ip_forward=1
    // MacOS: sysctl -w net.inet.ip.forwarding=1
    if cfg!(target_os = "macos") {
        let status = process::Command::new("sysctl").arg("-w").arg("net.inet.ip.forwarding=1").status().unwrap(); 
        assert!(status.success());
    } else if cfg!(target_os = "linux") {
        let status = process::Command::new("sysctl").arg("-w").arg("net.ipv4.ip_forward=1").status().unwrap(); 
        assert!(status.success());
    } else {
        unimplemented!()
    }


    let tun = TunDevice::create(tun_num)?; 
    // The server_client_id of the tun is not relevant for server
    tun.up(None);
    let tun_raw_fd = tun.file.as_raw_fd(); 
    let mut tun_socket = SourceFd(&tun_raw_fd);

    let mut poll = Mio_Poll::new()?; 
    let mut events = Events::with_capacity(1024); 
    poll.registry().register(&mut server_socket, Token(0), Interest::READABLE).map_err(|_| MioRegistryError)?;
    poll.registry().register(&mut tun_socket, Token(1), Interest::READABLE | Interest::WRITABLE).map_err(|_| MioRegistryError)?;

    let available_ids: Vec<u8> = (2..101).collect();  //allow 100 connections established between server and client

    let mut server = Device::Server { 
        server_socket: server_socket, 
        client_key_map: HashMap::new(), 
        tun: tun, 
        private_key: server_private_key, 
        available_ids: available_ids
    }; 

    loop {
        poll.poll(&mut events, None).map_err(|_| MioPollingError)?; // Replace with async tokio 
        for event in &events {
            match event.token() {
                Token(0) => { 
                    match server.read_socket(){
                        Ok((client_addr, msg)) => {
                            match msg {
                                Message::Request { .. } => {
                                    let (client_id, shared_secret_key) = server.process_request(&client_addr, msg)?; 
                                    println!("Shared secret key is {} with the client: {}", shared_secret_key, client_addr);
                                    server.set_shared_secret_key(shared_secret_key, Some((client_id, client_addr)))?; 
                                }, 
                                Message::PayLoad { client_id, data } => {
                                    let client_info = server.get_shared_secret_key(Some(client_id)); 
                                    match client_info {
                                        Ok(SecretData::SharedSecretClientData(address, shared_key)) => {
                                            // TODO: Decrypt data here with shared key
                                            println!("IP packet received: {:?}", data);
                                            server.write_tun(data)?;
                                        }, 
                                        Err(e) => eprintln!("The error: {}", e),
                                        _ => ()
                                    }
                                }
                                _ => ()  
                            }
                        }, 
                        Err(e) => eprintln!("The error: {}", e)
                    }
                }, 
                Token(1) => {
                    let mut buffer = [0u8; 2000];
                    match server.read_tun(&mut buffer) {
                        Ok(len ) => {
                            let data = &buffer[..len]; 
                            if len > 0  {
                                // the destination ip address is 16th to 20th bytes in ip packet => internal client ip address of the tun device
                                let client_internal_tun_address = &data[15..19]; 
                                // the client tun device configuration ifconfig utun* address1 address2, where address1 is internal destination ip address of the form 10.20.20.client_id
                                let client_id = client_internal_tun_address[3]; 
                                // TODO: Encrypt data here with shared key
                                let msg = Message::PayLoad { client_id: client_id, data: data.to_vec() }; 
                                let serialized = serde_json::to_string::<Message>(&msg).map_err(|e| SerialError(e.to_string()))?;
                                println!("IP packet sent: {:?}", &buffer[..len]);
                                match server.write_socket(serialized.as_bytes(), Some(client_id)) {
                                    Err(e) => println!("Error: {:?}", e), 
                                    _ => ()
                                };
                            }
                        }, 
                        Err(e) => eprintln!("The error: {}", e)
                    };
                }, 
                _ => ()
            }
        }
    }
}

pub fn client_side (client_addr : SocketAddr, server_addr: SocketAddr, tun_num: Option<u8>, client_private_key: BigInt, running: Arc<AtomicBool> ) -> Result<()> {
    let mut client_socket = UdpSocket::bind(client_addr).map_err(|e| SocketBindError(e.to_string()))?;

    let tun = TunDevice::create(tun_num)?; 
    let tun_raw_fd = tun.file.as_raw_fd(); 
    let mut tun_socket = SourceFd(&tun_raw_fd);

    let mut poll = Mio_Poll::new().map_err(|_| MioInitError)?; 
    let mut events = Events::with_capacity(1024); 
    poll.registry().register(&mut client_socket, Token(0), Interest::READABLE).map_err(|_| MioRegistryError)?;
    poll.registry().register(&mut tun_socket, Token(1), Interest::READABLE | Interest::WRITABLE).map_err(|_| MioRegistryError)?; 

    let mut client = Device::Client { client_socket: client_socket, server_addr: server_addr, tun: tun, shared_secret_key: None, private_key: client_private_key, id: None, default_gateway: None}; 

    client.initiate_handshake()?; 

    // MacOS
    // Get default gateway: 
    // route -n get default
    // Result: 
    //   route to: default
    //    destination: default
    //    mask: default
    //    gateway: __.__.__.__
    //    interface: en0
    //    flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
    //    recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
    //    0         0         0         0         0         0      1500         0 

    // Grab default: grep gateway
    //   gateway: __.__.__.__

    // Grab address only: awk '{print $2}' 
    // __.__.__.__

    // To change default gateway we need to first delete and then add our new default gateway: 
    // sudo route delete default
    // sudo route add default 10.20.20.1 

    // TODO: Need a way to revert back to original default gateway in case of program exit, due to interruptions such as ctrl + c or crashes

    loop {
        if !running.load(Ordering::SeqCst) {
            client.return_default_gateway(); 
            return Ok(()) 
        }
        poll.poll(&mut events, None).map_err(|_| MioPollingError)?; // Replace with async tokio 
        for event in &events {
            match event.token() {
                Token(0) => { 
                    match client.read_socket() {
                        Ok((addr, msg)) => {
                            match msg {
                                Message::Response { .. } => {
                                    let shared_secret_key = client.process_response(msg)?; 
                                    println!("Shared secret key is {}", shared_secret_key);
                                    client.set_shared_secret_key(shared_secret_key, None)?;
                                    client.setup_default_gateway();
                                }, 
                                Message::PayLoad { client_id, data } => {
                                    let shared_key = client.get_shared_secret_key(None)?; 
                                    // TODO: Decrypt data here with shared key
                                    println!("IP packet received: {:?}", data);
                                    client.write_tun(data)?;
                                }
                                _ => ()  // Implement data transmission
                            }
                        }, 
                        Err(e) => eprintln!("The error: {}", e)
                    }
                }, 
                Token(1) => {
                    let mut buffer = [0u8; 2000];
                    match client.read_tun(&mut buffer) {
                        Ok(len ) => {
                            let data = &buffer[..len]; 
                            if len > 0  {
                                let client_id = match client {
                                    Device::Client { id, .. } => id, 
                                    _ => None
                                };
                                match client_id {
                                    Some(id) => {
                                        let shared_key = client.get_shared_secret_key(None); 
                                        // TODO: Encrypt data here with shared key
                                        let msg = Message::PayLoad { client_id: id, data: data.to_vec() }; 
                                        let serialized = serde_json::to_string::<Message>(&msg).map_err(|e| SerialError(e.to_string()))?;
                                        println!("IP packet sent: {:?}", &buffer[..len]); 

                                        match client.write_socket(serialized.as_bytes(), None) {
                                            Err(e) => println!("Error: {:?}", e), 
                                            _ => ()
                                        };
                                    }, 
                                    None => {eprintln!("Connection not yet set between client and server")}
                                }
                            }
                        }, 
                        Err(e) => eprintln!("The error: {}", e)
                    };
                }, 
                _ => ()
            }
        }
    }
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
        tun.up(Some(8)); 

        let mut poll = Mio_Poll::new().unwrap();
        let mut events = Events::with_capacity(1024);
        poll.registry().register(&mut client_socket, Token(0), Interest::READABLE).unwrap();

        let client = Device::Client {client_socket: client_socket, server_addr: server_addr, tun : tun, shared_secret_key : None, private_key : client_private_key, id: None, default_gateway: None};
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
                            shared_secret_key = Some(client.process_response(msg).unwrap());
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
        tun.up(None); 

        let mut poll = Mio_Poll::new().unwrap();
        let mut events = Events::with_capacity(1024);

        poll.registry().register(&mut server_socket, Token(0), Interest::READABLE).unwrap();

        let mut server = Device::Server {server_socket: server_socket, client_key_map: HashMap::new(), tun : tun, private_key : server_private_key, available_ids: (2..101).collect()};

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
