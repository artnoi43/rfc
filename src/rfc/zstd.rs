use std::io::{self, Read, Write};

use super::error::RfcError;

/// Reads bytes from Reader `from` and compresses using level. Output is written to Writer `to`.
pub fn compress<R, W>(level: i32, mut from: R, to: W) -> Result<(), RfcError>
where
    R: Read,
    W: Write,
{
    let mut encoder =
        zstd::stream::Encoder::new(to, level).map_err(|err| RfcError::IoError(err))?;
    io::copy(&mut from, &mut encoder).map_err(|err| RfcError::IoError(err))?;
    encoder.finish().map_err(|err| RfcError::IoError(err))?;

    Ok(())
}

/// Decompresses from Reader `from` to Writer `to`
fn decompress<R, W>(r: R, mut w: W) -> Result<(), RfcError>
where
    R: Read,
    W: Write,
{
    let mut decoder = zstd::Decoder::new(r).map_err(|err| RfcError::IoError(err))?;
    io::copy(&mut decoder, &mut w).map_err(|err| RfcError::IoError(err))?;

    Ok(())
}

#[test]
fn test_compress() {
    let filename = "./Cargo.toml";
    let file_bytes = std::fs::read(filename).expect("failed to read file");

    let file = std::fs::File::open(filename).expect("failed to open file");

    let mut cmp = Vec::<u8>::with_capacity(file_bytes.len());
    if let Err(err) = compress(12, file, &mut cmp) {
        panic!("got compression error: {:?}", err);
    };

    let mut decmp = Vec::<u8>::with_capacity(cmp.len());
    if let Err(err) = decompress(&cmp[..], &mut decmp) {
        panic!("got decompression error: {:?}", err);
    }

    cmp.truncate(cmp.len());
    decmp.truncate(decmp.len());

    // Plaintext files should be fairly compressible
    assert!(cmp.len() < file_bytes.len());
    assert_eq!(file_bytes, decmp);
}

#[test]
fn test_compress_file() {
    // First compress to tmp_file, then tries to decompress it back out
    let filename = "./Cargo.toml";
    let tmp_filename = "./tmp.zst";
    let infile = std::fs::File::open(filename).expect("failed to open infile");
    let tmp_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open(tmp_filename)
        .expect("failed to create tmp file");

    if let Err(err) = compress(12, infile, &tmp_file) {
        std::fs::remove_file(tmp_filename).expect("failed to remove tmp_file");
        panic!("failed to compress to tmp_file: {:?}", err);
    }

    let compressed_len = tmp_file.metadata().expect("").len() as usize;
    let mut decmp = Vec::with_capacity(compressed_len);
    if let Err(err) = decompress(tmp_file, &mut decmp) {
        std::fs::remove_file(tmp_filename).expect("failed to remove tmp_file");
        panic!("failed to decompress tmp_file: {:?}", err)
    }

    std::fs::remove_file(tmp_filename).expect("failed to remove tmp_file");
    let uncompressed = std::fs::read(filename).expect("failed to read original file");

    assert_eq!(uncompressed, decmp);
}

/// For CLI args, `None` means no compression
#[derive(Clone, Copy, Debug)]
pub struct Level(pub Option<i32>);
impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(level) => write!(f, "{}", level.to_string()),
            None => write!(f, ""),
        }
    }
}
