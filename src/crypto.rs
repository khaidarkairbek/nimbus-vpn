use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305};
use num_bigint::BigInt;

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

// Diffie Hellman Key Exchange implementation
pub const DH_MODULUS: &'static str = "23";  // Placeholder values for testing
pub const DH_BASE: &'static str = "5";

pub fn generate_public_key(private_key: &BigInt) -> BigInt {
    let p: BigInt = DH_MODULUS.parse().unwrap(); //parse the modulus
    let g: BigInt = DH_BASE.parse().unwrap(); //parse the base

    g.modpow(private_key, &p)
}

pub fn generate_shared_key(public_key: &BigInt, private_key: &BigInt) -> BigInt {
    let p: BigInt = DH_MODULUS.parse().unwrap(); //parse the modulus

    public_key.modpow(private_key, &p)
}
