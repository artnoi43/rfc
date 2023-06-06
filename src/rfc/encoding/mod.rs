mod b64;
mod hex;

use clap;

pub use self::b64::*;
pub use self::hex::*;

#[derive(Copy, Clone, Debug, PartialEq, clap::ValueEnum)]
pub enum Encoding {
    Plain,
    Hex,
    B64,
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plain => write!(f, "plain"),
            Self::Hex => write!(f, "hex"),
            Self::B64 => write!(f, "b64"),
        }
    }
}
