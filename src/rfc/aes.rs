use aes::cipher::{generic_array::GenericArray, typenum::U16};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

use std::io::Write;

type BlockAes = GenericArray<u8, U16>;

pub struct CipherAes128 {}
pub struct CipherAes256 {}

impl super::Cipher for CipherAes128 {
    fn encrypt<T>(bytes: T, key: T) -> Vec<u8>
    where
        T: AsRef<[u8]>,
    {
        let mut blocks: Vec<BlockAes> = aes_blocks(bytes);
        Aes128::new(&GenericArray::from(aes_key(key))).encrypt_blocks(&mut blocks);

        aes_blocks_to_bytes(blocks)
    }

    fn decrypt<T>(bytes: T, key: T) -> Vec<u8>
    where
        T: AsRef<[u8]>,
    {
        let mut blocks: Vec<BlockAes> = aes_blocks(bytes);
        Aes128::new(&GenericArray::from(aes_key(key))).decrypt_blocks(&mut blocks);

        aes_blocks_to_bytes(blocks)
    }
}

impl super::Cipher for CipherAes256 {
    fn encrypt<T>(bytes: T, key: T) -> Vec<u8>
    where
        T: AsRef<[u8]>,
    {
        let mut blocks: Vec<BlockAes> = aes_blocks(bytes);
        Aes256::new(&GenericArray::from(aes_key(key))).encrypt_blocks(&mut blocks);

        aes_blocks_to_bytes(blocks)
    }

    fn decrypt<T>(bytes: T, key: T) -> Vec<u8>
    where
        T: AsRef<[u8]>,
    {
        let mut blocks: Vec<BlockAes> = aes_blocks(bytes);
        Aes256::new(&GenericArray::from(aes_key(key))).decrypt_blocks(&mut blocks);

        aes_blocks_to_bytes(blocks)
    }
}

fn aes_blocks<T>(bytes: T) -> Vec<BlockAes>
where
    T: AsRef<[u8]>,
{
    let chunks = super::bytes_chunks::<16, T>(bytes);
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

fn aes_key<const KEY_SIZE: usize, K>(key: K) -> [u8; KEY_SIZE]
where
    K: AsRef<[u8]>,
{
    let mut bytes = [0u8; KEY_SIZE];
    let mut buf = &mut bytes[..];

    buf.write_all(key.as_ref())
        .expect(format!("failed to create AES-{} key", 32 * 8).as_str());

    bytes
}

#[test]
fn test_aes_256() {
    use super::Cipher;

    let plaintext = include_str!("../../Cargo.toml");
    let key = "this_is_my_key";
    let ciphertext = CipherAes256::encrypt(plaintext.clone(), &key);
    assert!(ciphertext.len() != 0);

    let result = CipherAes256::decrypt(ciphertext, key.into());
    assert_eq!(
        plaintext,
        String::from_utf8(result).expect("failed to convert result back to string")
    );
}
