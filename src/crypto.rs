use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{AeadCore, ChaCha20Poly1305};
use num_bigint::BigInt;

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

fn pad_key_to_32_bytes(key: &[u8]) -> [u8; 32] {
    let mut padded_key_bytes = [0u8; 32];
    let length = std::cmp::min(key.len(), 32);
    padded_key_bytes[..length].copy_from_slice(&key[..length]);
    padded_key_bytes
}

pub fn encrypt_data(data: &[u8], key: &BigInt) -> Result<Vec<u8>, String> {
    let (_, key_in_bytes) = key.to_bytes_le(); //convert bigint key to a byte array (extract vec<u8>)
    let key_bytes_pad = pad_key_to_32_bytes(&key_in_bytes); //pad key to 32 bytes
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes_pad)); //create chacha20-poly1305 instance with the padded key
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); //generate random nonce
    let cipher_text = cipher.encrypt(&nonce, data).map_err(|e| e.to_string())?; //encrypt the data with generated nonce
    let mut result = nonce.to_vec(); //combine the nonce and ciphertext into a single vector
    result.extend(cipher_text);
    Ok(result)
}

pub fn decrypt_data(cipher_text: &[u8], key: &BigInt) -> Result<Vec<u8>, String> {
    let (_, key_in_bytes) = key.to_bytes_le(); //convert bigint key to a byte array (extract vec<u8>)
    let key_bytes_pad = pad_key_to_32_bytes(&key_in_bytes); //pad key to 32 bytes
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes_pad)); //create chacha20-poly1305 instance with the padded key
    let (nonce, cipher_text) = cipher_text.split_at(12); //split the cipher text into nonce and actual ciphertext
    let nonce = GenericArray::from_slice(nonce);
    let plain_text = cipher.decrypt(nonce, cipher_text).map_err(|e| e.to_string())?; //decrypt the ciphertext with the nonce
    Ok(plain_text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use num_bigint::BigInt;

    #[test]
    fn test_pad_key_to_32_bytes() {
        //test with a key shorter than 32 bytes
        let key = [1, 2, 3, 4, 5];
        let padded_key = pad_key_to_32_bytes(&key);
        assert_eq!(padded_key, [
            1, 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]);

        //test with a key exactly 32 bytes
        let key = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
        let padded_key = pad_key_to_32_bytes(&key);
        assert_eq!(padded_key, key);

        //test with a key longer than 32 bytes
        let key = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34
        ];
        let padded_key = pad_key_to_32_bytes(&key);
        assert_eq!(padded_key, [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32
        ]);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let data = b"Hello, world!";
        let key = BigInt::parse_bytes(b"1234567890123456789012345678901234567890", 10).unwrap();

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
        let key = BigInt::parse_bytes(b"9876543210987654321098765432109876543210", 10).unwrap();

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
        let key = BigInt::parse_bytes(b"1234567890123456789012345678901234567890", 10).unwrap();

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
        let key = BigInt::parse_bytes(b"9876543210987654321098765432109876543210", 10).unwrap();

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
        let key = BigInt::parse_bytes(b"1234567890123456789012345678901234567890", 10).unwrap();

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
            BigInt::parse_bytes(b"1234567890123456789012345678901234567890", 10).unwrap(),
            BigInt::parse_bytes(b"2234567890123456789012345678901234567890", 10).unwrap(),
            BigInt::parse_bytes(b"3234567890123456789012345678901234567890", 10).unwrap(),
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
