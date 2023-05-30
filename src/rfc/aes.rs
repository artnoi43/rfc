use aes::cipher::{generic_array::GenericArray, typenum::U16};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

use std::io::Write;

type BlockAes = GenericArray<u8, U16>;

pub struct CipherAes<const KEY_SIZE: usize> {
    blocks: Vec<BlockAes>,
    key: [u8; KEY_SIZE],
}

impl<const KEY_SIZE: usize> CipherAes<KEY_SIZE> {
    fn new(bytes: Vec<u8>, key: Vec<u8>) -> Self {
        return Self {
            blocks: aes_blocks(bytes),
            key: key_bytes::<KEY_SIZE, Vec<u8>>(key),
        };
    }
}

pub struct CipherAes128(CipherAes<16>);
pub struct CipherAes256(CipherAes<32>);

impl super::Cipher for CipherAes128 {
    fn new(bytes: Vec<u8>, key: Vec<u8>) -> Self {
        Self(CipherAes::<16>::new(bytes, key))
    }

    fn encrypt(mut self) -> Vec<u8> {
        Aes128::new(&GenericArray::from(self.0.key)).encrypt_blocks(&mut self.0.blocks);
        aes_blocks_to_bytes(self.0.blocks)
    }

    fn decrypt(mut self) -> Vec<u8> {
        Aes128::new(&GenericArray::from(self.0.key)).decrypt_blocks(&mut self.0.blocks);
        aes_blocks_to_bytes(self.0.blocks)
    }
}

impl super::Cipher for CipherAes256 {
    fn new(bytes: Vec<u8>, key: Vec<u8>) -> Self {
        Self(CipherAes::<32>::new(bytes, key))
    }

    fn encrypt(mut self) -> Vec<u8> {
        Aes256::new(&GenericArray::from(self.0.key)).encrypt_blocks(&mut self.0.blocks);
        aes_blocks_to_bytes(self.0.blocks)
    }

    fn decrypt(mut self) -> Vec<u8> {
        Aes256::new(&GenericArray::from(self.0.key)).decrypt_blocks(&mut self.0.blocks);
        aes_blocks_to_bytes(self.0.blocks)
    }
}

fn aes_blocks<B: AsRef<[u8]>>(bytes: B) -> Vec<BlockAes> {
    let chunks = super::bytes_chunks(bytes);

    let mut blocks: Vec<BlockAes> = Vec::with_capacity(chunks.len());
    for chunk in chunks {
        blocks.push(GenericArray::from(chunk));
    }

    blocks
}

fn aes_blocks_to_bytes(blocks: Vec<BlockAes>) -> Vec<u8> {
    blocks
        .into_iter()
        .map(|block| block.as_slice().to_owned())
        .flat_map(|slice| slice.into_iter().map(|byte| byte.to_owned()))
        .collect::<Vec<_>>()
}

fn key_bytes<const KEY_SIZE: usize, K: AsRef<[u8]>>(key: K) -> [u8; KEY_SIZE] {
    let mut bytes = [0u8; KEY_SIZE];
    let mut buf = &mut bytes[..];

    buf.write_all(key.as_ref())
        .expect(format!("failed to create AES-{} key", 32 * 8).as_str());
    bytes
}
