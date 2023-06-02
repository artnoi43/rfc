mod header;
pub mod raw;

use crate::rfc::file::RfcFile;
use crate::rfc::{Cipher, RfcError};
use header::HeaderAes;
use raw::{CipherRawAes128, CipherRawAes256};

use std::marker::PhantomData;

/// RawCipherAes does not handle padding during decryption,
/// so null bytes maybe in the decryption output.
pub trait RawCipherAes: Cipher<Output = (Vec<u8>, usize)> {}

impl RawCipherAes for CipherRawAes128 {}
impl RawCipherAes for CipherRawAes256 {}

/// Wrapper for CipherAes128 and CipherAes256 for decoding/encoding Header from/to Vec<u8>.
pub(crate) struct CipherAes<C>
where
    C: RawCipherAes,
{
    phantom: PhantomData<C>,
}

impl Cipher for CipherAes<CipherRawAes128> {
    type Output = Vec<u8>;

    fn encrypt<T, K>(bytes: T, key: K) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        encrypt::<CipherRawAes128, T, K>(bytes, key)
    }

    fn decrypt<T, K>(bytes: T, key: K) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        decrypt::<CipherRawAes128, T, K>(bytes, key)
    }
}

impl Cipher for CipherAes<CipherRawAes256> {
    type Output = Vec<u8>;

    fn encrypt<T, K>(bytes: T, key: K) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        encrypt::<CipherRawAes256, T, K>(bytes, key)
    }

    fn decrypt<T, K>(bytes: T, key: K) -> Result<Vec<u8>, RfcError>
    where
        T: AsRef<[u8]>,
        K: AsRef<[u8]>,
    {
        decrypt::<CipherRawAes256, T, K>(bytes, key)
    }
}

fn encrypt<C, T, K>(bytes: T, key: K) -> Result<Vec<u8>, RfcError>
where
    C: RawCipherAes,
    T: AsRef<[u8]>,
    K: AsRef<[u8]>,
{
    let (ciphertext, extra) = C::encrypt(bytes, key)?;

    encode_encryption_output(ciphertext, extra)
}

fn decrypt<C, T, K>(bytes: T, key: K) -> Result<Vec<u8>, RfcError>
where
    C: RawCipherAes,
    T: AsRef<[u8]>,
    K: AsRef<[u8]>,
{
    let f = RfcFile::<HeaderAes>::decode(bytes.as_ref())?;
    let (header, ciphertext) = (f.0, f.1);

    let (mut plaintext, extra) = C::decrypt(ciphertext, key)?;
    if extra != 0 {
        return Err(RfcError::Decryption(format!(
            "ciphertext not full AES blocks: got {} trail",
            extra
        )));
    }

    plaintext.truncate(plaintext.len() - 16 + header.extra);

    Ok(plaintext)
}

fn encode_encryption_output(ciphertext: Vec<u8>, extra: usize) -> Result<Vec<u8>, RfcError> {
    let output: RfcFile<HeaderAes> =
        RfcFile::<HeaderAes>(HeaderAes { extra, salt: None }, ciphertext);

    output.encode()
}

#[cfg(test)]
mod tests {
    use super::{CipherAes, CipherRawAes128, CipherRawAes256};
    use crate::rfc::tests::test_encryption;

    #[test]
    fn test_wrapped_aes() {
        test_encryption::<CipherAes<CipherRawAes256>>();
        test_encryption::<CipherAes<CipherRawAes128>>();
    }
}
