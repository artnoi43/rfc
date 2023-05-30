use clap;

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
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
