use thiserror::Error;

#[derive(Debug, Error)]
pub enum RfcError {
    #[error("not implemented")]
    NotImplemented(String),

    #[error("io error")]
    IoError(std::io::Error),

    #[error("serialize error")]
    Serialize(String),

    #[error("deserialize error")]
    Deserialize(String),

    #[error("encryption error")]
    Encryption(String),

    #[error("decryption error")]
    Decryption(String),

    #[error("compression error")]
    Compression,

    #[error("decompression error")]
    Decompression,
}
