use wincode::{SchemaRead, SchemaWrite}; 

#[derive(SchemaRead, SchemaWrite, Debug)]
pub enum Message {
    // keys in big-endian
    Request { public_key: Vec<u8> },
    Response { public_key: Vec<u8> },
    PayLoad { data: Vec<u8> },
}

#[cfg(test)]
mod tests {
    use crate::client::Client;
    use crate::server::Server;
    use crate::tun::config::Configuration;
    use std::net::SocketAddr;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_handshake() {
        let server_addr: SocketAddr = "127.0.0.1:8083".parse().unwrap();

        let server_thread = thread::spawn(move || {
            let mut server = Server::init(8083, &Configuration::default()).unwrap();
            let mut buffer = [0u8; 8192]; 

            for _ in 0..10 {
                if let Ok((client_addr, msg)) = server.read_socket(&mut buffer) {
                    let shared_secret_key =
                        Some(server.process_request(&client_addr, msg).unwrap());
                    return shared_secret_key;
                }

                thread::sleep(Duration::from_millis(10));
            }

            return None;
        });

        let client_thread = thread::spawn(move || {
            let mut client = Client::init(8082, server_addr, &Configuration::default()).unwrap();
            let mut buffer = [0u8; 8192];

            client.initiate_handshake().unwrap();

            for _ in 0..10 {
                if let Ok((_, msg)) = client.read_socket(&mut buffer) {
                    let shared_secret_key = Some(client.process_response(msg).unwrap());
                    return shared_secret_key;
                }

                thread::sleep(Duration::from_millis(10));
            }

            return None;
        });

        let client_shared = client_thread.join().unwrap();
        let server_shared = server_thread.join().unwrap();

        assert!(client_shared.is_some());
        assert_eq!(client_shared, server_shared);
    }
}
