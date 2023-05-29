use clap::{Parser, ValueEnum};

use std::path::PathBuf;

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

#[derive(Debug, Parser)]
pub struct Args {
    #[arg(short, long)]
    pub decrypt: bool,

    #[arg(short, long)]
    pub filename: PathBuf,

    #[arg(short, long)]
    pub outfile: PathBuf,

    #[arg(short, long, default_value_t = KeyType::Passphrase)]
    pub key_type: KeyType,

    #[arg(short, long, default_value_t = Encoding::Plain)]
    pub input_decoding: Encoding,

    #[arg(short, long, default_value_t = Encoding::Plain)]
    pub output_encoding: Encoding,
}
