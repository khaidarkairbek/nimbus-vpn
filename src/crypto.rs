use chacha20poly1305::ChaCha20Poly1305; 
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, NewAead}; 
use chacha20poly1305::aead::generic_array::GenericArray; 
use num_bigint::BigInt; 
use std::convert::TryInto; 
use chacha20poly1305::aead::generic_array::GenericArray;


fn pad_key_to_32_bytes(key: &[u8]) -> [u8; 32] {
    let mut padded_key_bytes = [0u8; 32]; //array of 32 bytes zeros
    let length = std::cmp::min(key.len(), 32); 
    padded_key_bytes[..length].copy_from_slice(&key[..length]); //copy key bytes to the padded arr
    padded_key_bytes
}


pub fn encrypt_data(data: &[u8], key: &BigInt) -> Result<Vec<u8>, String>{
    let key_in_bytes= key.to_bytes_le(); //bigint key to a byte arr
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


// Diffie Hellman Key Exchange implementation
const DH_MODULUS: &'static str = "23";  // Placeholder values for testing
const DH_BASE: &'static str = "5";

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
