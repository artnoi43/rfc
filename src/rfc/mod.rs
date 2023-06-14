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
use self::encoding::Encoding;
use self::error::RfcError;
use self::pbkdf2::{generate_salt, pbkdf2_key};
use self::wrapper::WrapperBytes;

/// core wraps all core rfc logic into a function.
/// It writes its output to `output`.
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

    post_process_write(decrypt, bytes, codec, compress, &mut output)
}

/// core_buf wraps all core rfc logic into a function.
/// It returns the output of rfc core as bytes
pub fn core_buf<R>(
    decrypt: bool,
    key: Vec<u8>,
    mode: Mode,
    input: R,
    input_len: Option<usize>,
    codec: encoding::Encoding,
    compress: bool,
) -> Result<Vec<u8>, RfcError>
where
    R: Read,
{
    let bytes = pre_process(decrypt, input, input_len, codec, compress)?;
    let bytes = crypt(decrypt, bytes, key, mode)?;

    post_process_buf(decrypt, bytes, codec, compress)
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
        true => decode_read(codec, input, input_len),
        false => match compress {
            true => compress_read(input, input_len),
            false => buf::read_bytes(input, input_len),
        },
    }
}

/// Derives new key from `key` using PBKDF2 and use the new key to encrypt/decrypt bytes.
fn crypt(decrypt: bool, bytes: Vec<u8>, key: Vec<u8>, mode: Mode) -> Result<Vec<u8>, RfcError> {
    match decrypt {
        false => rfc_encrypt(bytes, key, mode),
        true => rfc_decrypt(bytes, key, mode),
    }
}

/// Post-processes bytes and writes the result to output.
fn post_process_write<W: Write>(
    decrypt: bool,
    bytes: Vec<u8>,
    codec: encoding::Encoding,
    compress: bool,
    output: &mut W,
) -> Result<usize, RfcError> {
    match decrypt {
        true => match compress {
            true => decompress_write(output, bytes),
            false => buf::write_bytes(output, &bytes),
        },

        false => encode_write(codec, output, bytes),
    }
}

/// Post-processes bytes and returns the result as byte buffer
fn post_process_buf(
    decrypt: bool,
    bytes: Vec<u8>,
    codec: encoding::Encoding,
    compress: bool,
) -> Result<Vec<u8>, RfcError> {
    match decrypt {
        true => match compress {
            true => decompress_buf(bytes),
            false => Ok(bytes),
        },

        false => encode_buf(codec, bytes),
    }
}

/// Expand key with some random salt, and uses the derived key to encrypt `bytes`.
/// The encryption output is concatenated with salt and archived using rkyv.
fn rfc_encrypt(bytes: Vec<u8>, key: Vec<u8>, mode: Mode) -> Result<Vec<u8>, RfcError> {
    let salt = generate_salt()?;

    let ciphertext = match mode {
        Mode::Aes128 => CipherAes128::encrypt(
            bytes,
            pbkdf2_key::<{ CipherAes128::KEY_SIZE }, _, _>(key, &salt)?,
        ),
        Mode::Aes256 => CipherAes256::encrypt(
            bytes,
            pbkdf2_key::<{ CipherAes256::KEY_SIZE }, _, _>(key, &salt)?,
        ),
    }?;

    WrapperBytes::<Vec<u8>>(salt, ciphertext).encode()
}

/// Extracts salt and ciphertext embedded in `bytes` and uses salt to derive the encryption key,
/// and uses the key to decrypt data, returning the bytes.
fn rfc_decrypt(bytes: Vec<u8>, key: Vec<u8>, mode: Mode) -> Result<Vec<u8>, RfcError> {
    let wrapped = WrapperBytes::<Vec<u8>>::decode_archived(&bytes)?;
    let (salt, bytes) = (&wrapped.0, &wrapped.1);

    match mode {
        Mode::Aes128 => CipherAes128::decrypt(
            bytes.to_vec(),
            pbkdf2_key::<{ CipherAes128::KEY_SIZE }, _, _>(key, &salt)?,
        ),
        Mode::Aes256 => CipherAes256::decrypt(
            bytes.to_vec(),
            pbkdf2_key::<{ CipherAes256::KEY_SIZE }, _, _>(key, &salt)?,
        ),
    }
}

/// Encode `bytes` and write the result to `output`.
fn encode_write<W, T>(codec: Encoding, output: &mut W, bytes: T) -> Result<usize, RfcError>
where
    W: Write,
    T: AsRef<[u8]>,
{
    match codec {
        Encoding::B64 => encoding::encode_b64(&mut bytes.as_ref(), output),
        Encoding::Hex => buf::write_bytes(output, encoding::encode_hex_buf(bytes)),
        _ => buf::write_bytes(output, &bytes),
    }
}

/// Encode `bytes` and return the result buffer.
fn encode_buf(codec: Encoding, bytes: Vec<u8>) -> Result<Vec<u8>, RfcError> {
    match codec {
        Encoding::B64 => encoding::encode_b64_buf(&mut bytes.as_slice(), bytes.len()),
        Encoding::Hex => Ok(encoding::encode_hex_buf(bytes)),
        _ => Ok(bytes),
    }
}

/// Reads bytes from `input` and decodes it to a byte vector accoding to codec
fn decode_read<R>(
    codec: Encoding,
    mut input: R,
    input_len: Option<usize>,
) -> Result<Vec<u8>, RfcError>
where
    R: Read,
{
    match codec {
        Encoding::Plain => buf::read_bytes(input, input_len),
        Encoding::B64 => {
            // Allocate a buffer that would fit plain bytes decoded from Base64-encoded bytes of `input_len` length
            let mut buf: Vec<u8> =
                Vec::with_capacity(encoding::prealloc_from_b64(input_len.unwrap_or(0)));

            encoding::decode_b64(&mut input, &mut buf)?;

            buf.truncate(buf.len());
            Ok(buf)
        }
        encoding::Encoding::Hex => {
            let bytes = buf::read_bytes(input, input_len)?;
            encoding::decode_hex_buf(bytes)
        }
    }
}

/// Reads bytes from `input`, encoding the original uncompressed length to the output bytes
/// so that we can accurately allocate a buffer for decompression.
fn compress_read<R>(input: R, input_len: Option<usize>) -> Result<Vec<u8>, RfcError>
where
    R: Read,
{
    let (uncompressed_len, compressed): (usize, Vec<u8>) = match input_len {
        // If input_len is not given, then read to bytes before compress so that we know uncompressed length
        None => {
            let bytes = buf::read_bytes(input, Some(1024))?;
            (bytes.len(), lz4::compress_bytes(&bytes))
        }
        Some(len) => {
            let compressed = lz4::compress_to_bytes_sized(input, input_len)?;
            (len, compressed)
        }
    };

    WrapperBytes::<usize>(uncompressed_len, compressed).encode()
}

/// Decompresses bytes and write the decompressed bytes to output.
fn decompress_write<W>(output: W, bytes: Vec<u8>) -> Result<usize, RfcError>
where
    W: Write,
{
    use rkyv::vec::ArchivedVec;
    let with_len = WrapperBytes::<usize>::decode_archived(&bytes)?;
    let (_, compressed): (u32, &ArchivedVec<_>) = (with_len.0, &with_len.1);

    lz4::decompress_reader_to_writer(&mut compressed.as_slice(), output)
}

/// Decompresses `bytes` to a new accurately allocated buffer
fn decompress_buf(bytes: Vec<u8>) -> Result<Vec<u8>, RfcError> {
    use rkyv::vec::ArchivedVec;
    let with_len = WrapperBytes::<usize>::decode_archived(&bytes)?;
    let (uncompressed_len, compressed): (u32, &ArchivedVec<_>) = (with_len.0, &with_len.1);

    lz4::decompress_to_bytes_sized(compressed.as_slice(), Some(uncompressed_len as usize))
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
        core, core_buf, crypt,
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

            compresses.iter().for_each(|compress| {
                encodings.iter().for_each(|codec| {
                    modes.iter().for_each(|mode| {
                        // Open again for every sub-test
                        let infile = open_file(filename, false).unwrap();
                        println!(
                            "testing with mode: {mode}, compress: {compress}, encoding: {codec}"
                        );

                        test_rfc_core(
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

    fn test_rfc_core<R>(
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

    #[test]
    fn test_core_buf() {
        let encodings: Vec<Encoding> = vec![Plain, Hex, B64];
        let modes: Vec<Mode> = vec![Mode::Aes128, Mode::Aes256];
        let compresses = vec![false, true];

        let key = b"this_is_my_key".to_vec();
        test_cases().into_iter().for_each(|plaintext| {
            compresses.iter().for_each(|compress| {
                encodings.iter().for_each(|codec| {
                    modes.iter().for_each(|mode| {
                        println!(
                            "testing with mode: {mode}, compress: {compress}, encoding: {codec}"
                        );

                        test_rfc_core_buf(plaintext.clone(), key.clone(), *mode, *codec, *compress)
                    })
                })
            })
        })
    }

    fn test_rfc_core_buf(
        plaintext: Vec<u8>,
        key: Vec<u8>,
        mode: Mode,
        codec: Encoding,
        compress: bool,
    ) {
        let ciphertext = core_buf(
            false,
            key.clone(),
            mode,
            &plaintext[..],
            Some(plaintext.len()),
            codec,
            compress,
        )
        .expect("encryption failed");

        let decrypted = core_buf(
            true,
            key,
            mode,
            &ciphertext[..],
            Some(ciphertext.len()),
            codec,
            compress,
        )
        .expect("decryption failed");

        assert_eq!(plaintext, decrypted);
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
