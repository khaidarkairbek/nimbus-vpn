use num_bigint::{BigUint};
use serde::{Deserialize, Serialize};
use std::str;

#[derive(Serialize, Deserialize, Debug)]
pub enum Message {
    Request {
        public_key: BigUint,
    },
    Response {
        public_key: BigUint,
    },
    PayLoad {
        data: Vec<u8>,
    },
}


#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;
    use std::thread;
    use crate::client::Client;
    use crate::server::Server;
    use crate::tun::config::Configuration;

    #[test]
    fn test_handshake() {
        let server_addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();

        let server_thread = thread::spawn(move || {
            let mut server = Server::init(8081, &Configuration::default()).unwrap();

            for _ in 0..10 {
                if let Ok((client_addr, msg)) = server.read_socket() {
                    let shared_secret_key = Some(server.process_request(&client_addr, msg).unwrap());
                    return shared_secret_key;
                }

                thread::sleep(Duration::from_millis(10));
            }

            return None;
        });

        let client_thread = thread::spawn(move || {
            let mut client = Client::init(8080, server_addr, &Configuration::default()).unwrap(); 

            client.initiate_handshake().unwrap(); 

            for _ in 0..10 {
                if let Ok((_, msg)) = client.read_socket() {
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