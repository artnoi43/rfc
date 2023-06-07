mod header;

/// Basic AES cipher, with implementation from "aes" extern crate.
/// This crate wraps the extern crate with extra logic, i.e. padding
/// bytes as well as removing the padding during decryption.
///
/// Since we need padding information to remove padding when decrypting,
/// the encryption output bytes are serialized from `RfcFile<AesHeader>`.
use aes::cipher::{generic_array::GenericArray, typenum::U16};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

use std::io::Write;

use crate::rfc::buf::bytes_chunks;
use crate::rfc::error::RfcError;
use crate::rfc::wrapper::WrapperBytes;
use crate::rfc::Cipher;
use header::HeaderAes;

const AES_BLOCKSIZE: usize = 16;

type BlockAes = GenericArray<u8, U16>;

/// Raw AES 128 cipher. It uses the implementation from crate "aes".
/// It handles padding removal when decrypting a padded ciphertext.
pub struct CipherAes128 {}
/// Raw AES 256 cipher. It uses the implementation from crate "aes"
/// It handles padding removal when decrypting a padded ciphertext.
pub struct CipherAes256 {}

impl Cipher for CipherAes128 {
    const KEY_SIZE: usize = 16;

    fn encrypt<T, K>(bytes: T, key: K) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let (mut blocks, extra) = aes_blocks(bytes);
        Aes128::new(&GenericArray::from(aes_key(key))).encrypt_blocks(&mut blocks);

        let ciphertext = aes_blocks_to_bytes(blocks);
        encode_encryption_output(ciphertext, extra)
    }

    fn decrypt<T, K>(bytes: T, key: K) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let infile = WrapperBytes::<HeaderAes>::decode_archived(bytes.as_ref())?;
        let ciphertext = &infile.1;

        let (mut blocks, ciphertext_extra) = aes_blocks(ciphertext);
        if ciphertext_extra != 0 {
            return Err(RfcError::Decryption(format!(
                "input not full AES blocks: got {} extra trailing",
                ciphertext_extra
            )));
        }

        Aes128::new(&GenericArray::from(aes_key(key))).decrypt_blocks(&mut blocks);
        let plaintext = aes_blocks_to_bytes(blocks);

        let extra = (&infile.0).0 as usize;
        Ok(truncate_padding(plaintext, extra))
    }
}

impl Cipher for CipherAes256 {
    const KEY_SIZE: usize = 32;

    fn encrypt<T, K>(bytes: T, key: K) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let (mut blocks, extra) = aes_blocks(bytes);
        Aes256::new(&GenericArray::from(aes_key(key))).encrypt_blocks(&mut blocks);

        let blocks = aes_blocks_to_bytes(blocks);
        encode_encryption_output(blocks, extra)
    }

    fn decrypt<T, K>(bytes: T, key: K) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let infile = WrapperBytes::<HeaderAes>::decode_archived(bytes.as_ref())?;
        let ciphertext = &infile.1;

        let (mut blocks, ciphertext_extra) = aes_blocks(ciphertext);
        if ciphertext_extra != 0 {
            return Err(RfcError::Decryption(format!(
                "input not full AES blocks: got {} extra trailing",
                ciphertext_extra
            )));
        }

        Aes256::new(&GenericArray::from(aes_key(key))).decrypt_blocks(&mut blocks);
        let plaintext = aes_blocks_to_bytes(blocks);

        let extra = (&infile.0).0 as usize;
        Ok(truncate_padding(plaintext, extra))
    }
}

fn aes_blocks<T>(bytes: T) -> (Vec<BlockAes>, usize)
where
    T: AsRef<[u8]>,
{
    let (chunks, extra) = bytes_chunks::<AES_BLOCKSIZE, T>(bytes);
    let mut blocks: Vec<BlockAes> = Vec::with_capacity(chunks.len());

    for chunk in chunks {
        blocks.push(GenericArray::from(chunk));
    }

    (blocks, extra)
}

fn aes_blocks_to_bytes(blocks: Vec<BlockAes>) -> Vec<u8> {
    blocks
        .into_iter()
        .map(|block| block.as_slice().to_owned())
        .flat_map(|slice| slice.into_iter().map(|byte| byte.to_owned()))
        .collect()
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

fn truncate_padding(mut plaintext: Vec<u8>, extra: usize) -> Vec<u8> {
    let final_len = plaintext.len().checked_sub(AES_BLOCKSIZE).unwrap_or(0) + extra;
    plaintext.truncate(final_len);

    plaintext
}

fn encode_encryption_output(ciphertext: Vec<u8>, extra: usize) -> Result<Vec<u8>, RfcError> {
    let output: WrapperBytes<HeaderAes> = WrapperBytes::<HeaderAes>(HeaderAes(extra), ciphertext);

    output.encode()
}

#[cfg(test)]
pub mod tests {
    use super::{CipherAes128, CipherAes256};
    use crate::rfc::tests::test_cipher;

    #[test]
    fn test_wrapped_aes() {
        test_cipher::<CipherAes256>();
        test_cipher::<CipherAes128>();
    }
}
