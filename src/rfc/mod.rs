mod aes;

use self::aes::{CipherAes128, CipherAes256};
use crate::cli;

pub enum Mode {
    Aes128,
    Aes256,
}

pub trait Cipher {
    // Encryption consumes the cipher
    fn encrypt(bytes: Vec<u8>, key: Vec<u8>) -> Vec<u8>;
    // Decryption consumes the cipher
    fn decrypt(bytes: Vec<u8>, key: Vec<u8>) -> Vec<u8>;
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
