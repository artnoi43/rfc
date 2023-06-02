use base64::Engine as _;
use base64::{self, engine::general_purpose};
use password_hash::Salt;
use pbkdf2::pbkdf2_hmac;
use rand_core::{OsRng, RngCore};
use sha2::Sha256;

use super::error::RfcError;

const PBKDF2_ROUNDS: u32 = 4096;

pub fn pbkdf2_key<const L: usize, T, U>(password: T, salt: &U) -> Result<[u8; L], RfcError>
where
    T: AsRef<[u8]>,
    U: AsRef<[u8]>,
{
    let mut key = [0u8; L];

    pbkdf2_hmac::<Sha256>(password.as_ref(), salt.as_ref(), PBKDF2_ROUNDS, &mut key);
    Ok(key)
}

pub fn generate_salt() -> Result<Vec<u8>, RfcError> {
    // 16-byte random Base64 for salt generation (will be 22 bytes in Base64)
    let mut b64 = rand_b64()?;
    b64.truncate(22);

    let salt =
        Salt::from_b64(std::str::from_utf8(&b64).expect("b64 is not UTF8")).map_err(|err| {
            RfcError::Encryption(format!(
                "failed to generate salt from b64: {}",
                err.to_string()
            ))
        })?;

    Ok(salt.to_string().as_bytes().to_vec())
}

fn rand_b64() -> Result<Vec<u8>, RfcError> {
    // 16-byte random Base64 for salt generation (will be 22 bytes in Base64)
    let mut b64 = Vec::<u8>::new();
    b64.resize(16 * 4 / 3 + 4, 0);

    {
        let mut rand = [0u8; 16];
        OsRng.fill_bytes(&mut rand);
        general_purpose::STANDARD_NO_PAD
            .encode_slice(rand, &mut b64)
            .map_err(|err| {
                RfcError::Encryption(format!(
                    "failed to encode rand bytes to b64: {}",
                    err.to_string(),
                ))
            })?;
    }

    Ok(b64)
}

#[test]
fn test_gen_salt() {
    [0..5].into_iter().for_each(|_| {
        if let Err(err) = generate_salt() {
            eprintln!("got error: {:?}", err);
            panic!("generate_salt returned an error");
        }
    });
}

#[test]
fn test_gen_key() {
    let password = b"password";
    let salt = generate_salt().expect("failed to generate salt");

    let key1 = pbkdf2_key::<32, &[u8], Vec<u8>>(&password[..], &salt)
        .expect("failed to create pbkdf2 key");

    assert_eq!(key1.len(), 32);

    let key2 = pbkdf2_key::<32, &[u8], Vec<u8>>(&password[..], &salt)
        .expect("failed to create pbkdf2 key");

    assert_eq!(key1, key2);
}

#[test]
fn test_pbkdf2_encryption() {
    use super::Cipher;

    let password = b"password";
    let salt = generate_salt().expect("failed to generate salt");
    let key1 = pbkdf2_key::<32, _, _>(password, &salt).expect("failed to generate pbkdf2 key");

    let plaintext = include_str!("./mod.rs").as_bytes();
    let ciphertext = super::aes::CipherAes256::encrypt(plaintext, key1).expect("failed to encrypt");

    let key2 = pbkdf2_key::<32, _, _>(password, &salt).expect("failed to generate pbkdf2 key");
    let decrypted = super::aes::CipherAes256::decrypt(ciphertext, key2).expect("failed to decrypt");

    assert_eq!(plaintext, decrypted);
}
