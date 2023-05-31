pub mod aes;
pub mod buf;
pub mod encoding;
mod file;

use serde::{Deserialize, Serialize};

use self::aes::{CipherAes128, CipherAes256};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub enum Mode {
    Aes128,
    Aes256,
}

pub trait Cipher {
    fn crypt<T>(bytes: T, key: T, decrypt: bool) -> Vec<u8>
    where
        T: AsRef<[u8]>,
    {
        if decrypt {
            return Self::decrypt(bytes, key);
        }

        Self::encrypt(bytes, key)
    }

    fn encrypt<T>(bytes: T, key: T) -> Vec<u8>
    where
        T: AsRef<[u8]>;

    fn decrypt<T>(bytes: T, key: T) -> Vec<u8>
    where
        T: AsRef<[u8]>;
}

pub fn pre_process(bytes: Vec<u8>, decrypt: bool, codec: encoding::Encoding) -> Vec<u8> {
    bytes
}

pub fn crypt<T>(bytes: T, decrypt: bool, key: T, cipher: Mode) -> Vec<u8>
where
    T: AsRef<[u8]>,
{
    match cipher {
        Mode::Aes128 => CipherAes128::crypt(bytes, key, decrypt),
        Mode::Aes256 => CipherAes256::crypt(bytes, key, decrypt),
    }
}

pub fn post_process(bytes: Vec<u8>, decrypt: bool, codec: encoding::Encoding) -> Vec<u8> {
    bytes
}
