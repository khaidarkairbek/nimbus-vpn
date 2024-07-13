use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305};
use num_bigint::BigInt;
use crate::dev::{Device, DH_MODULUS, DH_BASE, Message}; //import the device enum and constants
use serde_json;

fn pad_key_to_32_bytes(key: &[u8]) -> [u8; 32] {
    let mut padded_key_bytes = [0u8; 32]; //array of 32 bytes initialized to zero
    let length = std::cmp::min(key.len(), 32);
    padded_key_bytes[..length].copy_from_slice(&key[..length]); //copy key bytes to the padded array
    padded_key_bytes
}

pub fn encrypt_data(data: &[u8], key: &BigInt) -> Result<Vec<u8>, String> {
    let (_, key_in_bytes) = key.to_bytes_le(); //bigint key to a byte array (extract vec<u8>)
    let key_bytes_pad = pad_key_to_32_bytes(&key_in_bytes); //pad key to 32 bytes
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes_pad)); //create chacha20-poly1305 instance with the padded key
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); //generate random nonce
    let cipher_text = cipher.encrypt(&nonce, data).map_err(|e| e.to_string())?; //encrypt the data with generated nonce
    let mut result = nonce.to_vec(); //combine the nonce and ciphertext into a single vector
    result.extend(cipher_text);
    Ok(result)
}

pub fn decrypt_data(cipher_text: &[u8], key: &BigInt) -> Result<Vec<u8>, String> {
    let (_, key_in_bytes) = key.to_bytes_le(); //bigint key to a byte array (extract vec<u8>)
    let key_bytes_pad = pad_key_to_32_bytes(&key_in_bytes); //pad key to 32 bytes
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes_pad)); //create chacha20-poly1305 instance with the padded key
    let (nonce, cipher_text) = cipher_text.split_at(12); //split the cipher text into nonce and actual ciphertext
    let nonce = GenericArray::from_slice(nonce);
    let plain_text = cipher.decrypt(nonce, cipher_text).map_err(|e| e.to_string())?; //decrypt the ciphertext with the nonce
    Ok(plain_text)
}

//initiates the handshake by calculating the client public key using diffie-hellman algorithm
//and sending the request with the public key to the server
pub fn initiate_handshake(device: &Device) -> Result<(), String> {
    match device {
        Device::Client {
            client_socket,
            server_addr,
            private_key,
            ..
        } => {
            let p: BigInt = DH_MODULUS.parse().unwrap(); //parse the modulus
            let g: BigInt = DH_BASE.parse().unwrap(); //parse the base

            let client_public_key = g.modpow(private_key, &p); //calculate the client's public key

            let request_msg = Message::Request { client_public_key }; //create a request message

            let serialized = serde_json::to_string(&request_msg).map_err(|e| e.to_string())?; //serialize the message to json

            client_socket
                .send_to(serialized.as_bytes(), *server_addr) //send the request to the server
                .map_err(|e| e.to_string())?;

            println!("request sent to the server {}", server_addr);

            Ok(())
        }
        _ => Err("handshake can be initiated by client only".to_string()),
    }
}
