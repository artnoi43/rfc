pub mod aes;
pub mod buf;
pub mod encoding;
pub mod error;
pub mod pbkdf2;
pub mod zstd;

mod wrapper;

use self::aes::{CipherAes128, CipherAes256};
use self::pbkdf2::{generate_salt, pbkdf2_key};
use self::wrapper::WrapperBytes;
use error::RfcError;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Aes128,
    Aes256,
}

pub trait Cipher {
    const KEY_SIZE: usize;

    fn crypt<T, U>(bytes: T, key: U, decrypt: bool) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        U: AsRef<[u8]>,
    {
        if decrypt {
            return Self::decrypt(bytes, key);
        }

        Self::encrypt(bytes, key)
    }

    fn encrypt<T, U>(bytes: T, key: U) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        U: AsRef<[u8]>;

    fn decrypt<T, U>(bytes: T, key: U) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        U: AsRef<[u8]>;
}

/// Pre-processes input bytes
pub fn pre_process(
    decrypt: bool,
    bytes: Vec<u8>,
    codec: encoding::Encoding,
) -> Result<Vec<u8>, RfcError> {
    Ok(bytes)
}

/// Derives new key from `key` using PBKDF2 and use the new key to encrypt/decrypt bytes.
pub fn crypt(
    decrypt: bool,
    bytes: Vec<u8>,
    key: Vec<u8>,
    cipher: Mode,
) -> Result<Vec<u8>, RfcError> {
    // Extract encoded salt if decrypt, otherwise generate new salt
    let (salt, bytes) = match decrypt {
        false => (generate_salt()?, bytes),
        true => {
            let wrapped_bytes = WrapperBytes::<Vec<u8>>::decode_archived(&bytes)?;
            (wrapped_bytes.0.to_vec(), wrapped_bytes.1.to_vec())
        }
    };

    let result = match cipher {
        Mode::Aes128 => CipherAes128::crypt(
            bytes,
            pbkdf2_key::<{ CipherAes128::KEY_SIZE }, _, _>(key, &salt)?,
            decrypt,
        ),
        Mode::Aes256 => CipherAes256::crypt(
            bytes,
            pbkdf2_key::<{ CipherAes256::KEY_SIZE }, _, _>(key, &salt)?,
            decrypt,
        ),
    }?;

    // Encode salt to output bytes if encrypt, otherwise just return plaintext bytes.
    match decrypt {
        false => WrapperBytes::<Vec<u8>>(salt.into(), result).encode(),
        true => Ok(result),
    }
}

/// Post-processes output bytes.
pub fn post_process(
    decrypt: bool,
    bytes: Vec<u8>,
    codec: encoding::Encoding,
) -> Result<Vec<u8>, RfcError> {
    Ok(bytes)
}

#[cfg(test)]
pub mod tests {
    use super::{Cipher, Mode};

    #[test]
    fn test_crypt() {
        test_rfc_crypt(Mode::Aes128);
        test_rfc_crypt(Mode::Aes256);
    }

    pub fn test_cases() -> Vec<&'static str> {
        vec![
            include_str!("../../Cargo.toml"),
            include_str!("./mod.rs"),
            "foo",
            "",
        ]
    }

    pub fn test_rfc_crypt(cipher: Mode) {
        use super::crypt;

        test_cases().into_iter().for_each(|plaintext| {
            let plaintext = plaintext.as_bytes();
            let key = b"this_is_my_key";

            let ciphertext = crypt(false, plaintext.to_vec(), key.clone().to_vec(), cipher)
                .expect("failed to encrypt");

            let decrypt_result =
                crypt(true, ciphertext, key.to_vec(), cipher).expect("failed to decrypt");

            assert_eq!(plaintext, decrypt_result);
        })
    }

    pub fn test_cipher<C: Cipher>() {
        test_cases().into_iter().for_each(|plaintext| {
            let plaintext = plaintext.as_bytes();
            let key = "this_is_my_key".as_bytes();
            let ciphertext = C::encrypt(plaintext.clone(), &key).expect("encryption failed");
            assert!(ciphertext.len() != 0);

            let plaintext_result =
                C::decrypt::<Vec<u8>, &[u8]>(ciphertext, key.into()).expect("decryption failed");
            assert_eq!(plaintext, plaintext_result);
        });
    }
}
