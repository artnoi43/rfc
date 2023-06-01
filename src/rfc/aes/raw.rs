pub use super::*;

use aes::cipher::{generic_array::GenericArray, typenum::U16};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes256};

use std::io::Write;

use crate::rfc;
use crate::rfc::error::RfcError;

type BlockAes = GenericArray<u8, U16>;

/// Raw AES 128 cipher. It does not handle padding during decryption,
/// so null bytes maybe in the decryption output.
pub struct CipherRawAes128 {}
/// Raw AES 256 cipher. It does not handle padding during decryption,
/// so null bytes maybe in the decryption output.
pub struct CipherRawAes256 {}

impl super::Cipher for CipherRawAes128 {
    type Output = (Vec<u8>, usize);

    fn encrypt<T, K>(bytes: T, key: K) -> Result<Self::Output, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let (mut blocks, extra) = aes_blocks(bytes);
        Aes128::new(&GenericArray::from(aes_key(key))).encrypt_blocks(&mut blocks);

        Ok((aes_blocks_to_bytes(blocks), extra))
    }

    fn decrypt<T, K>(bytes: T, key: K) -> Result<Self::Output, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let (mut blocks, extra) = aes_blocks(bytes);
        Aes128::new(&GenericArray::from(aes_key(key))).decrypt_blocks(&mut blocks);

        Ok((aes_blocks_to_bytes(blocks), extra))
    }
}

impl super::Cipher for CipherRawAes256 {
    type Output = (Vec<u8>, usize);

    fn encrypt<T, K>(bytes: T, key: K) -> Result<Self::Output, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let (mut blocks, extra) = aes_blocks(bytes);
        Aes256::new(&GenericArray::from(aes_key(key))).encrypt_blocks(&mut blocks);

        Ok((aes_blocks_to_bytes(blocks), extra))
    }

    fn decrypt<T, K>(bytes: T, key: K) -> Result<Self::Output, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        let (mut blocks, extra) = aes_blocks(bytes);
        if extra != 0 {
            return Err(RfcError::Decryption(format!(
                "input not full AES blocks: got {} trail",
                extra
            )));
        }

        Aes256::new(&GenericArray::from(aes_key(key))).decrypt_blocks(&mut blocks);

        Ok((aes_blocks_to_bytes(blocks), extra))
    }
}

fn aes_blocks<T>(bytes: T) -> (Vec<BlockAes>, usize)
where
    T: AsRef<[u8]>,
{
    let (chunks, extra) = rfc::buf::bytes_chunks::<16, T>(bytes);
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

#[cfg(test)]
pub mod tests {
    use crate::rfc::Cipher;

    pub fn test_raw_aes_encryption<C: Cipher<Output = (Vec<u8>, usize)>>() {
        let plaintext = "1111111111111111".as_bytes();
        let key = "this_is_my_key".as_bytes();
        let (ciphertext, _) = C::encrypt(plaintext.clone(), &key).expect("encryption failed");
        assert!(ciphertext.len() != 0);

        let (plaintext_result, _) =
            C::decrypt::<Vec<u8>, &[u8]>(ciphertext, key.into()).expect("decryption failed");

        assert_eq!(plaintext, plaintext_result);
    }

    #[test]
    fn test_raw_aes_128() {
        use super::super::CipherRawAes128;
        test_raw_aes_encryption::<CipherRawAes128>();
    }

    #[test]
    fn test_raw_aes_256() {
        use super::super::CipherRawAes256;
        test_raw_aes_encryption::<CipherRawAes256>();
    }
}
