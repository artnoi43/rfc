pub mod aes;
pub mod buf;
pub mod cipher;
pub mod encoding;
pub mod error;
pub mod lz4;
pub mod pbkdf2;
pub mod wrapper;

use std::io::{Read, Write};

// Exports as lib
use self::aes::{CipherAes128, CipherAes256};
use self::cipher::Cipher;
use self::pbkdf2::{generate_salt, pbkdf2_key};
use self::wrapper::WrapperBytes;

use error::RfcError;

/// core wraps all core logic of rfc into a function.
pub fn core<R, W>(
    decrypt: bool,
    key: Vec<u8>,
    mode: Mode,
    input: R,
    input_len: Option<usize>,
    mut output: W,
    codec: encoding::Encoding,
    compress: bool,
) -> Result<usize, RfcError>
where
    R: Read,
    W: Write,
{
    let bytes = pre_process(decrypt, input, input_len, codec, compress)?;
    let bytes = crypt(decrypt, bytes, key, mode)?;

    post_process_and_write_out(decrypt, bytes, codec, compress, &mut output)
}

/// Pre-processes input bytes
fn pre_process<R>(
    decrypt: bool,
    mut input: R,
    input_len: Option<usize>,
    codec: encoding::Encoding,
    compress: bool,
) -> Result<Vec<u8>, RfcError>
where
    R: Read,
{
    match decrypt {
        true => {
            match codec {
                encoding::Encoding::Plain => buf::bytes_from_reader(input, input_len),
                encoding::Encoding::B64 => {
                    // Allocate a buffer that would fit plain bytes decoded from Base64-encoded bytes of `input_len` length
                    let mut buf: Vec<u8> =
                        Vec::with_capacity(encoding::prealloc_from_b64(input_len.unwrap_or(0)));

                    encoding::decode_b64(&mut input, &mut buf)?;

                    buf.truncate(buf.len());
                    Ok(buf)
                }
                encoding::Encoding::Hex => {
                    let bytes = buf::bytes_from_reader(input, input_len)?;
                    encoding::decode_hex(bytes)
                }
            }
        }
        false => {
            match compress {
                true => {
                    let (uncompressed_len, compressed): (usize, Vec<u8>) = match input_len {
                        // If input_len is not given, then read to bytes before compress so that we know uncompressed length
                        None => {
                            let bytes = buf::bytes_from_reader(input, Some(1024))?;
                            (bytes.len(), lz4::compress_bytes(&bytes))
                        }
                        Some(len) => {
                            let compressed = lz4::compress_to_bytes_sized(input, input_len)?;
                            (len, compressed)
                        }
                    };

                    WrapperBytes::<usize>(uncompressed_len, compressed).encode()
                }

                false => buf::bytes_from_reader(input, input_len),
            }
        }
    }
}

/// Derives new key from `key` using PBKDF2 and use the new key to encrypt/decrypt bytes.
pub fn crypt(decrypt: bool, bytes: Vec<u8>, key: Vec<u8>, mode: Mode) -> Result<Vec<u8>, RfcError> {
    // Extract encoded salt if decrypt, otherwise generate new salt
    let (salt, bytes) = match decrypt {
        false => (generate_salt()?, bytes),
        true => {
            let wrapped_bytes = WrapperBytes::<Vec<u8>>::decode(&bytes)?;
            (wrapped_bytes.0, wrapped_bytes.1)
        }
    };

    let result = match mode {
        Mode::Aes128 => CipherAes128::crypt(
            bytes,
            pbkdf2_key::<{ CipherAes128::KEY_SIZE }, _, _>(key, &salt)?,
            decrypt,
        ),
        Mode::Aes256 => CipherAes256::crypt(
            bytes,
            pbkdf2_key::<{ CipherAes256::KEY_SIZE }, _, _>(key, &salt)?,
            decrypt,
        ),
    }?;

    // Encode salt to output bytes if encrypt, otherwise just return plaintext bytes.
    match decrypt {
        false => WrapperBytes::<Vec<u8>>(salt.into(), result).encode(),
        true => Ok(result),
    }
}

/// Post-processes output bytes.
pub fn post_process_and_write_out<W: Write>(
    decrypt: bool,
    bytes: Vec<u8>,
    codec: encoding::Encoding,
    compress: bool,
    output: &mut W,
) -> Result<usize, RfcError> {
    use rkyv::vec::ArchivedVec;
    match decrypt {
        true => match compress {
            true => {
                let with_len = WrapperBytes::<usize>::decode_archived(&bytes)?;
                let (uncompressed_len, compressed): (u32, &ArchivedVec<_>) =
                    (with_len.0, &with_len.1);

                lz4::decompress_reader_to_writer(&mut compressed.as_slice(), output)
            }
            false => write_out(output, &bytes),
        },

        false => match codec {
            encoding::Encoding::B64 => encoding::encode_b64(&mut bytes.as_slice(), output),
            encoding::Encoding::Hex => write_out(output, encoding::encode_hex(bytes)),
            _ => write_out(output, &bytes),
        },
    }
}

fn write_out<W, T>(mut w: W, data: T) -> Result<usize, RfcError>
where
    W: Write,
    T: AsRef<[u8]>,
{
    w.write(data.as_ref()).map_err(|err| RfcError::IoError(err))
}

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Mode {
    Aes128,
    Aes256,
}
impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes128 => write!(f, "aes128"),
            Self::Aes256 => write!(f, "aes256"),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::{
        buf::open_file,
        buf::read_file,
        core, crypt,
        encoding::Encoding::{self, *},
        Cipher, Mode,
    };
    use std::io::Read;

    #[test]
    fn test_crypt() {
        test_rfc_crypt(Mode::Aes128);
        test_rfc_crypt(Mode::Aes256);
    }

    #[test]
    fn test_core_file() {
        let modes: Vec<Mode> = vec![Mode::Aes128, Mode::Aes256];
        let encodings: Vec<Encoding> = vec![Plain, Hex, B64];
        let compresses: [bool; 2] = [false, true];

        let infiles = vec!["./Cargo.toml"];
        let key = b"this_is_my_key".to_vec();

        infiles.into_iter().for_each(|filename| {
            let mut infile = open_file(filename, false).unwrap();
            let infile_len = Some(infile.metadata().unwrap().len() as usize);
            let mut plaintext = Vec::with_capacity(infile_len.unwrap());

            infile.read_to_end(&mut plaintext).unwrap();

            modes.iter().for_each(|mode| {
                compresses.iter().for_each(|compress| {
                    encodings.iter().for_each(|codec| {
                        // Open again for every sub-test
                        let infile = open_file(filename, false).unwrap();
                        println!(
                            "testing with mode: {mode}, compress: {compress}, encoding: {codec}"
                        );

                        test_core(
                            plaintext.clone(),
                            *mode,
                            key.clone(),
                            &infile,
                            infile_len,
                            *codec,
                            *compress,
                        )
                    });
                });
            });
        });
    }

    fn test_core<R>(
        expected_bytes: Vec<u8>,
        mode: Mode,
        key: Vec<u8>,
        input: R,
        input_len: Option<usize>,
        codec: Encoding,
        compress: bool,
    ) where
        R: Read,
    {
        let mut ciphertext = Vec::<u8>::with_capacity(input_len.unwrap());
        let (encrypt, decrypt) = (false, true);

        println!(
            "plaintext len: {} cap: {}",
            expected_bytes.len(),
            expected_bytes.capacity()
        );

        core(
            encrypt,
            key.clone(),
            mode,
            input,
            input_len,
            &mut ciphertext,
            codec,
            compress,
        )
        .expect("encryption failed");

        println!(
            "ciphertext len: {} cap: {}",
            ciphertext.len(),
            ciphertext.capacity()
        );

        let mut decrypted = Vec::<u8>::with_capacity(expected_bytes.len());
        println!(
            "decrypted created len: {} cap: {}",
            decrypted.len(),
            decrypted.capacity()
        );

        core(
            decrypt,
            key,
            mode,
            &ciphertext[..],
            Some(ciphertext.len()),
            &mut decrypted,
            codec,
            compress,
        )
        .expect("decryption failed");

        println!(
            "decrypted len: {} cap: {}",
            decrypted.len(),
            decrypted.capacity()
        );

        assert_eq!(expected_bytes, decrypted);
    }

    pub fn test_cases() -> Vec<Vec<u8>> {
        vec![
            include_bytes!("../../Cargo.toml").to_vec(),
            include_bytes!("./mod.rs").to_vec(),
            "foo".as_bytes().to_vec(),
            "".as_bytes().to_vec(),
        ]
    }

    pub fn test_rfc_crypt(cipher: Mode) {
        test_cases().into_iter().for_each(|plaintext| {
            let plaintext = plaintext;
            let key = b"this_is_my_key";

            let ciphertext = crypt(false, plaintext.to_vec(), key.clone().to_vec(), cipher)
                .expect("failed to encrypt");

            let decrypt_result =
                crypt(true, ciphertext, key.to_vec(), cipher).expect("failed to decrypt");

            assert_eq!(plaintext, decrypt_result);
        })
    }

    pub fn test_cipher<C: Cipher>() {
        test_cases().into_iter().for_each(|plaintext| {
            let plaintext = plaintext;
            let key = "this_is_my_key".as_bytes();
            let ciphertext = C::encrypt(plaintext.clone(), &key).expect("encryption failed");
            assert!(ciphertext.len() != 0);

            let plaintext_result =
                C::decrypt::<Vec<u8>, &[u8]>(ciphertext, key.into()).expect("decryption failed");
            assert_eq!(plaintext, plaintext_result);
        });
    }
}
