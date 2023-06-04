use clap::{Parser, ValueEnum};

use crate::rfc::{encoding::Encoding, Mode};

#[derive(Debug, Parser)]
#[clap(
    author = "github.com/artnoi43",
    version,
    about = "A simple, stupid Rust clone of gfc - a file encryption utility"
)]
pub struct Args {
    /// Input file
    #[arg(value_parser = validate_filename)]
    pub filename: Filename,

    /// Encryption cipher/mode to use
    #[arg(short, long, default_value_t = Cipher::Aes256)]
    pub cipher: Cipher,

    #[arg(short, long, default_value_t = false)]
    /// Decrypt file
    pub decrypt: bool,

    #[arg(short, long, value_parser = validate_filename)]
    /// Output file
    pub outfile: Filename,

    #[arg(short, long = "key", default_value_t = KeyType::Passphrase)]
    /// Encryption key type - can be either passphrase or key file
    pub key_type: KeyType,

    #[arg(short = 'f', long, value_parser = validate_filename)]
    /// Encryprion key file
    pub key_file: Option<Filename>,

    #[arg(short = 'z', long, default_value_t = false)]
    /// Compress using LZ4
    pub compress: bool,

    #[arg(short, long, default_value_t = Encoding::Plain)]
    /// Encoding to decode input
    pub encoding: Encoding,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum Cipher {
    Aes128,
    Aes256,
}
impl std::fmt::Display for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Aes128 => write!(f, "aes128"),
            Self::Aes256 => write!(f, "aes256"),
        }
    }
}
impl Cipher {
    pub fn rfc_mode(&self) -> Mode {
        match self {
            Self::Aes128 => Mode::Aes128,
            Self::Aes256 => Mode::Aes256,
        }
    }
}

#[derive(Clone, Debug, ValueEnum)]
pub enum KeyType {
    Passphrase,
    KeyFile,
}
impl std::fmt::Display for KeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Passphrase => write!(f, "passphrase"),
            Self::KeyFile => write!(f, "keyfile"),
        }
    }
}

type Filename = String;
fn validate_filename(name: &str) -> Result<Filename, String> {
    if name.is_empty() {
        return Err(String::from("empty filename"));
    }

    Ok(name.to_string())
}

#[test]
fn test_validate_filename() {
    assert!(validate_filename("").is_err());
    assert!(validate_filename("foo").is_ok());
}
