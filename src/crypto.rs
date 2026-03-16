use anyhow::Result;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

use crate::error::CryptoError::*;

// RFC 3526 Group 14 - 2048-bit MODP Diffie-Hellman parameters
const DH_MODULUS_HEX: &str = "  
    FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
    29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
    EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
    E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
    EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
    C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
    83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
    670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
    E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
    DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
    15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
    "; 
const DH_BASE: u32 = 2;

pub fn generate_public_key(private_key: &BigUint) -> BigUint {
    let p = BigUint::parse_bytes(DH_MODULUS_HEX.replace(' ', "").as_bytes(), 16)
        .expect("DH_MODULUS_HEX is a valid compile-time constant");
    let g = BigUint::from(DH_BASE);
    g.modpow(private_key, &p)
}

pub fn generate_shared_key(public_key: &BigUint, private_key: &BigUint) -> BigUint {
    let p = BigUint::parse_bytes(DH_MODULUS_HEX.replace(' ', "").as_bytes(), 16)
        .expect("DH_MODULUS_HEX is a valid compile-time constant");
    public_key.modpow(private_key, &p)
}

fn derive_key_from_secret(shared_secret: &BigUint) -> [u8; 32] {
    let bytes = shared_secret.to_bytes_be();
    Sha256::digest(&bytes).into()
}

pub fn encrypt_data(data: &[u8], key: &BigUint) -> Result<Vec<u8>> {
    let key_bytes = derive_key_from_secret(key);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes));
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let cipher_text = cipher
        .encrypt(&nonce, data)
        .map_err(|e| EncryptError(e.to_string()))?;
    let mut result = nonce.to_vec();
    result.extend(cipher_text);
    Ok(result)
}

pub fn decrypt_data(cipher_text: &[u8], key: &BigUint) -> Result<Vec<u8>> {
    let key_bytes = derive_key_from_secret(key);
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes));
    let (nonce, cipher_text) = cipher_text.split_at(12);
    let nonce = GenericArray::from_slice(nonce);
    let plain_text = cipher
        .decrypt(nonce, cipher_text)
        .map_err(|e| DecryptError(e.to_string()))?;
    Ok(plain_text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::BigUint;
    use rand::Rng;

    #[test]
    fn test_derive_key_is_deterministic() {
        let secret = BigUint::from(12345u32);
        let key1 = derive_key_from_secret(&secret);
        let key2 = derive_key_from_secret(&secret);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_derive_key_differs_for_different_secrets() {
        let key1 = derive_key_from_secret(&BigUint::from(1u32));
        let key2 = derive_key_from_secret(&BigUint::from(2u32));
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"Hello, world!";
        let key = BigUint::parse_bytes(b"1234567890123456789012345678901234567890", 10).unwrap();

        //encrypt the data
        let encrypted_data = encrypt_data(data, &key).expect("Encryption failed");

        //decrypt the data
        let decrypted_data = decrypt_data(&encrypted_data, &key).expect("Decryption failed");

        //verify that the decrypted data matches the original data
        assert_eq!(data.to_vec(), decrypted_data);
    }

    #[test]
    fn test_encrypt_decrypt_random_data() {
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; 128]; //generate 128 bytes of random data
        rng.fill(&mut data[..]);
        let key = BigUint::parse_bytes(b"9876543210987654321098765432109876543210", 10).unwrap();

        //encrypt the data
        let encrypted_data = encrypt_data(&data, &key).expect("Encryption failed");

        //decrypt the data
        let decrypted_data = decrypt_data(&encrypted_data, &key).expect("Decryption failed");

        //verify that the decrypted data matches the original data
        assert_eq!(data, decrypted_data);
    }

    #[test]
    fn test_encrypt_decrypt_with_empty_data() {
        let data = b"";
        let key = BigUint::parse_bytes(b"1234567890123456789012345678901234567890", 10).unwrap();

        //encrypt the data
        let encrypted_data = encrypt_data(data, &key).expect("Encryption failed");

        //decrypt the data
        let decrypted_data = decrypt_data(&encrypted_data, &key).expect("Decryption failed");

        //verify that the decrypted data matches the original data
        assert_eq!(data.to_vec(), decrypted_data);
    }

    #[test]
    fn test_encrypt_decrypt_with_large_data() {
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; 1024 * 1024]; //generate 1mb of random data
        rng.fill(&mut data[..]);
        let key = BigUint::parse_bytes(b"9876543210987654321098765432109876543210", 10).unwrap();

        //encrypt the data
        let encrypted_data = encrypt_data(&data, &key).expect("Encryption failed");

        //decrypt the data
        let decrypted_data = decrypt_data(&encrypted_data, &key).expect("Decryption failed");

        //verify that the decrypted data matches the original data
        assert_eq!(data, decrypted_data);
    }

    #[test]
    fn test_decrypt_with_modified_ciphertext() {
        let data = b"Hello, world!";
        let key = BigUint::parse_bytes(b"1234567890123456789012345678901234567890", 10).unwrap();

        //encrypt the data
        let mut encrypted_data = encrypt_data(data, &key).expect("Encryption failed");

        {
            //modify the ciphertext
            let last_index = encrypted_data.len() - 1;
            encrypted_data[last_index] ^= 0xff; //flip the last byte
        }

        //attempt to decrypt the data
        let decrypted_result = decrypt_data(&encrypted_data, &key);

        //verify that decryption fails
        assert!(decrypted_result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_with_varied_keys() {
        let data = b"Hello, world!";
        let keys = vec![
            BigUint::parse_bytes(b"1234567890123456789012345678901234567890", 10).unwrap(),
            BigUint::parse_bytes(b"2234567890123456789012345678901234567890", 10).unwrap(),
            BigUint::parse_bytes(b"3234567890123456789012345678901234567890", 10).unwrap(),
        ];

        for key in keys {
            //encrypt the data
            let encrypted_data = encrypt_data(data, &key).expect("Encryption failed");

            //decrypt the data
            let decrypted_data = decrypt_data(&encrypted_data, &key).expect("Decryption failed");

            //verify that the decrypted data matches the original data
            assert_eq!(data.to_vec(), decrypted_data);
        }
    }
}
