use thiserror::Error;

#[derive(Error, Debug)]
#[error("clipboard store error")]
pub enum AppError {
    #[error("not implemented")]
    NotImplemented(String),

    #[error("rfc bug")]
    Bug(String),

    #[error("no such file")]
    NoSuchFile(std::io::Error),

    #[error("empty clipboard sent")]
    Empty,

    #[error("io error")]
    IoError(#[from] std::io::Error),

    #[error("bad utf-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}
