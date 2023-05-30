mod aes;

use self::aes::{CipherAes128, CipherAes256};
use crate::cli;

pub enum Mode {
    Aes128,
    Aes256,
}

pub trait Cipher {
    // Give bytes and key when creating cipher
    fn new(bytes: Vec<u8>, key: Vec<u8>) -> Self
    where
        Self: Sized;

    // Encryption consumes the cipher
    fn encrypt(self) -> Vec<u8>;
    // Decryption consumes the cipher
    fn decrypt(self) -> Vec<u8>;
}

fn pre_process(bytes: Vec<u8>, decrypt: bool, key: Vec<u8>, codec: cli::Encoding) -> Vec<u8> {
    bytes
}

fn crypt(bytes: Vec<u8>, decrypt: bool, key: Vec<u8>, cipher: Mode) -> Vec<u8> {
    bytes
}

fn post_process(bytes: Vec<u8>, decrypt: bool, codec: cli::Encoding) -> Vec<u8> {
    bytes
}

pub fn bytes_chunks<const BLOCK_SIZE: usize, B: AsRef<[u8]>>(bytes: B) -> Vec<[u8; BLOCK_SIZE]> {
    let mut chunks: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(bytes.as_ref().len() / BLOCK_SIZE);

    for chunk in bytes.as_ref().array_chunks::<BLOCK_SIZE>() {
        chunks.push(*chunk)
    }

    chunks
}
