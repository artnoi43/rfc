use clap::{Parser, ValueEnum};

#[derive(Clone, Debug, ValueEnum)]
pub enum Encoding {
    Plain,
    Hex,
    B64,
    Bin,
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::Hex => write!(f, "hex"),
            Self::B64 => write!(f, "b64"),
            Self::Bin => write!(f, "bin"),
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
fn validate_filename_test() {
    assert!(validate_filename("").is_err());
    assert!(validate_filename("foo").is_ok());
}

#[derive(Debug, Parser)]
#[clap(
    author = "github.com/artnoi43",
    version,
    about = "A simple, stupid Rust clone of gfc - a file encryption utility"
)]
pub struct Args {
    // Input file
    #[arg(value_parser = validate_filename)]
    pub filename: Filename,

    #[arg(short, long, default_value_t = false)]
    // Decrypt file
    pub decrypt: bool,

    #[arg(short, long, value_parser = validate_filename)]
    // Output file
    pub outfile: Filename,

    #[arg(short, long = "key", default_value_t = KeyType::Passphrase)]
    // Encryption key type - can be either passphrase or key file
    pub key_type: KeyType,

    #[arg(short = 'f', long, value_parser = validate_filename)]
    // Encryprion key file
    pub key_file: Option<Filename>,

    #[arg(short, long, default_value_t = Encoding::Plain)]
    // Encoding to decode input
    pub encoding: Encoding,
}
