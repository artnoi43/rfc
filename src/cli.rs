use clap::{Parser, ValueEnum};

use crate::rfc::encoding;

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

    #[arg(short = 'z', long, value_parser = validate_zstd_arg, default_value_t = ZstdArg(None))]
    /// ZSTD compression level
    pub compress: ZstdArg,

    #[arg(short, long, default_value_t = encoding::Encoding::Plain)]
    /// Encoding to decode input
    pub encoding: encoding::Encoding,
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

#[derive(Clone, Debug)]
pub struct ZstdArg(Option<i32>);
impl std::fmt::Display for ZstdArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(level) => write!(f, "{}", level.to_string()),
            None => write!(f, ""),
        }
    }
}

fn validate_zstd_arg(level: &str) -> Result<ZstdArg, String> {
    if level.is_empty() {
        return Ok(ZstdArg(None));
    }

    let level: i32 = level
        .parse()
        .map_err(|_| format!("failed to parse string {} to i32", level))?;

    if level < 0 {
        return Err(format!("level is negative: {}", level));
    }

    if level == 0 {
        return Ok(ZstdArg(None));
    }

    if level > 22 {
        return Err(format!("level is greater than 22: {}", level));
    }

    Ok(ZstdArg(Some(level)))
}

#[test]
fn test_validate_zstd_arg() {
    vec![
        ("", Result::<ZstdArg, String>::Ok(ZstdArg(None))),
        ("0", Ok(ZstdArg(None))),
        ("3", Ok(ZstdArg(Some(3)))),
        ("+3", Ok(ZstdArg(Some(3)))),
        ("21", Ok(ZstdArg(Some(21)))),
        ("foo", Err(String::new())),
        ("-3", Err(String::new())),
        ("32", Err(String::new())),
        ("-32", Err(String::new())),
    ]
    .into_iter()
    .for_each(|test| {
        let result = validate_zstd_arg(test.0);

        if test.1.is_err() {
            assert!(result.is_err());
            return;
        }

        let expected: ZstdArg = test.1.unwrap();
        let actual: ZstdArg = result.unwrap();
        assert_eq!(actual.0, expected.0);
    })
}
