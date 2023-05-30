pub mod aes;

use self::aes::{CipherAes128, CipherAes256};
use crate::cli;

use std::io::Write;

pub enum Mode {
    Aes128,
    Aes256,
}

pub trait Cipher {
    fn crypt<T: AsRef<[u8]>>(bytes: T, key: T, decrypt: bool) -> Vec<u8> {
        if decrypt {
            return Self::decrypt(bytes, key);
        }

        Self::encrypt(bytes, key)
    }
    // Encryption consumes the cipher
    fn encrypt<T: AsRef<[u8]>>(bytes: T, key: T) -> Vec<u8>;
    // Decryption consumes the cipher
    fn decrypt<T: AsRef<[u8]>>(bytes: T, key: T) -> Vec<u8>;
}

pub fn pre_process(bytes: Vec<u8>, decrypt: bool, codec: cli::Encoding) -> Vec<u8> {
    bytes
}

pub fn crypt<T: AsRef<[u8]>>(bytes: T, decrypt: bool, key: T, cipher: Mode) -> Vec<u8> {
    match cipher {
        Mode::Aes128 => CipherAes128::crypt(bytes, key, decrypt),
        Mode::Aes256 => CipherAes256::crypt(bytes, key, decrypt),
    }
}

pub fn post_process(bytes: Vec<u8>, decrypt: bool, codec: cli::Encoding) -> Vec<u8> {
    bytes
}

pub fn bytes_chunks<const BLOCK_SIZE: usize, B: AsRef<[u8]>>(bytes: B) -> Vec<[u8; BLOCK_SIZE]> {
    let chunks = {
        let len = bytes.as_ref().len();
        match len % BLOCK_SIZE {
            0 => len / BLOCK_SIZE,
            _ => len / BLOCK_SIZE + 1,
        }
    };

    let mut chunks: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(chunks);

    let arrays = bytes.as_ref().array_chunks::<BLOCK_SIZE>();
    let remainder = arrays.remainder();

    for chunk in arrays {
        chunks.push(*chunk)
    }

    if remainder.len() != 0 {
        let mut chunk = [0u8; BLOCK_SIZE];
        fill(&mut chunk, remainder);

        chunks.push(chunk);
    }

    chunks
}

// Fills buf with bytes
fn fill(mut buf: &mut [u8], bytes: &[u8]) {
    buf.write(bytes).expect("filling bytes failed");
}
