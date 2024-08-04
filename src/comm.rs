use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use std::sync::Arc;
use std::{net::SocketAddr, collections::HashMap, process};
use num_bigint::BigInt;
use crate::dev::{Device, Message, SecretData};
use crate::tun::TunDevice;
use anyhow::Result;
use crate::error::{
    CommError::*, SocketError::*
}; 

pub async fn server_side (server_addr : SocketAddr, tun_num : Option<u8>, server_private_key : BigInt) -> Result<()> {   
    let server_socket = UdpSocket::bind(server_addr).await.map_err(|e| SocketBindError(e.to_string()))?;

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


    let available_ids: Vec<u8> = (2..101).collect();  //allow 100 connections established between server and client

    let server = Arc::new(Mutex::new(Device::Server { 
        server_socket: server_socket, 
        client_key_map: HashMap::new(), 
        tun: tun, 
        private_key: server_private_key, 
        available_ids: available_ids
    })); 

    let mut buffer = [0u8; 2000];
    loop {
        tokio::select! {
            result = read_socket(&server) => {
                match result {
                    Ok((client_addr, msg)) => {
                        let mut server_guard = server.lock().await;
                        match msg { 
                            Message::Request { .. } => {
                                let (client_id, shared_secret_key) = server_guard.process_request(&client_addr, msg).await?; 
                                println!("Shared secret key is {} with the client: {}", shared_secret_key, client_addr);
                                server_guard.set_shared_secret_key(shared_secret_key, Some((client_id, client_addr)))?; 
                            }, 
                            Message::PayLoad { client_id, data } => {
                                let client_info = server_guard.get_shared_secret_key(Some(client_id)); 
                                match client_info {
                                    Ok(SecretData::SharedSecretClientData(address, shared_key)) => {
                                        // TODO: Decrypt data here with shared key
                                        println!("IP packet received: {:?}", data);
                                        server_guard.write_tun(data).await?;
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
            result = read_tun(&server, &mut buffer) => {
                match result {
                    Ok(len ) => {
                        let data = &buffer[..len]; 
                        let mut server_guard = server.lock().await;
                        if len > 0  {
                            // the destination ip address is 16th to 20th bytes in ip packet => internal client ip address of the tun device
                            let client_internal_tun_address = &data[15..19]; 
                            // the client tun device configuration ifconfig utun* address1 address2, where address1 is internal destination ip address of the form 10.20.20.client_id
                            let client_id = client_internal_tun_address[3]; 
                            // TODO: Encrypt data here with shared key
                            let msg = Message::PayLoad { client_id: client_id, data: data.to_vec() }; 
                            let serialized = serde_json::to_string::<Message>(&msg).map_err(|e| SerialError(e.to_string()))?;
                            println!("IP packet sent: {:?}", &buffer[..len]);
                            match server_guard.write_socket(serialized.as_bytes(), Some(client_id)).await {
                                Err(e) => println!("Error: {:?}", e), 
                                _ => ()
                            };
                        }
                    }, 
                    Err(e) => eprintln!("The error: {}", e)
                }
            }
        }
    }
}

pub async fn client_side (client_addr : SocketAddr, server_addr: SocketAddr, tun_num: Option<u8>, client_private_key: BigInt ) -> Result<()> { 
    let client_socket = UdpSocket::bind(client_addr).await.map_err(|e| SocketBindError(e.to_string()))?;

    let tun = TunDevice::create(tun_num)?;

    let client = Arc::new(Mutex::new(Device::Client { 
        client_socket: client_socket, 
        server_addr: server_addr, 
        tun: tun, 
        shared_secret_key: None, 
        private_key: client_private_key, 
        id: None, 
        default_gateway: None
    }));

    client.lock().await.initiate_handshake().await?;

    let token = CancellationToken::new(); 
    let cloned_token = token.clone();

    tokio::spawn(async move {
        signal::ctrl_c().await.unwrap();
        token.cancel(); 
    });

    let mut buffer = [0u8; 2000];
    loop {
        tokio::select! {
            _ = cloned_token.cancelled() => {
                client.lock().await.return_default_gateway();
                return Ok(())
            }
            result = read_socket(&client) => {
                match result {
                    Ok((addr, msg)) => {
                        let mut client_guard = client.lock().await; 
                        match msg {
                            Message::Response { .. } => {
                                let shared_secret_key = client_guard.process_response(msg)?; 
                                println!("Shared secret key is {}", shared_secret_key);
                                client_guard.set_shared_secret_key(shared_secret_key, None)?;
                                client_guard.setup_default_gateway();
                            }, 
                            Message::PayLoad { client_id, data } => {
                                let shared_key = client_guard.get_shared_secret_key(None)?; 
                                // TODO: Decrypt data here with shared key
                                println!("IP packet received: {:?}", data);
                                client_guard.write_tun(data).await?;
                            }
                            _ => ()  // Implement data transmission
                        }
                    }, 
                    Err(e) => eprintln!("The error: {}", e)
                }
            }, 
            result = read_tun(&client, &mut buffer) => {
                match result {
                    Ok(len) => {
                        let data = &buffer[..len];
                        let mut client_guard = client.lock().await; 
                        if len > 0  {
                            let client_id = match *client_guard {
                                Device::Client { id, .. } => id, 
                                _ => None
                            };
                            match client_id {
                                Some(id) => {
                                    let shared_key = client_guard.get_shared_secret_key(None); 
                                    // TODO: Encrypt data here with shared key
                                    let msg = Message::PayLoad { client_id: id, data: data.to_vec() }; 
                                    let serialized = serde_json::to_string::<Message>(&msg).map_err(|e| SerialError(e.to_string()))?;
                                    println!("IP packet sent: {:?}", &buffer[..len]); 

                                    match client_guard.write_socket(serialized.as_bytes(), None).await {
                                        Err(e) => println!("Error: {:?}", e), 
                                        _ => ()
                                    };
                                }, 
                                None => {eprintln!("Connection not yet set between client and server")}
                            }
                        }
                    }, 
                    Err(e) => eprintln!("The error: {}", e)
                }
            }
        }
    }
}

pub async fn read_socket(device: &Arc<Mutex<Device>>) -> Result<(SocketAddr, Message)> {
    let mut dev = device.lock().await; 
    dev.read_socket().await
}

pub async fn read_tun(device: &Arc<Mutex<Device>>, buffer: &mut [u8]) -> Result<usize> {
    let mut dev = device.lock().await; 
    dev.read_tun(buffer).await
}