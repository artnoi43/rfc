use crate::rfc::error::RfcError;

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
