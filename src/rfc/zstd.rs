use std::io::{self, Read, Write};

use super::error::RfcError;

/// Pre-allocates a buffer with capacity `prealloc` if any,
/// and compresses data from `from` into the buffer,
/// truncating any buffer extra capacity before returning the buffer.
pub fn compress_to_bytes<R>(
    level: i32,
    from: R,
    prealloc: Option<usize>,
) -> Result<Vec<u8>, RfcError>
where
    R: Read,
{
    let mut buf = match prealloc {
        None => Vec::<u8>::new(),
        Some(cap) => Vec::<u8>::with_capacity(cap),
    };

    compress(level, from, &mut buf)?;
    buf.truncate(buf.len());

    Ok(buf)
}

/// Pre-allocates a buffer with capacity `prealloc` if any,
/// and decompresses data from `from` into the buffer
/// truncating any buffer extra capacity before returning the buffer.
pub fn decompress_to_bytes<R>(mut from: R, prealloc: Option<usize>) -> Result<Vec<u8>, RfcError>
where
    R: Read,
{
    let mut buf = match prealloc {
        None => Vec::<u8>::new(),
        Some(cap) => Vec::<u8>::with_capacity(cap),
    };

    decompress(&mut from, &mut buf)?;
    buf.truncate(buf.len());

    Ok(buf)
}

/// Reads bytes from Reader `from` and compresses using level. Output is written to Writer `to`.
fn compress<R, W>(level: i32, mut from: R, to: W) -> Result<(), RfcError>
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
fn test_compress_bytes() {
    let filename = "./Cargo.lock";

    let infile = std::fs::File::open(filename).expect("failed to open infile");

    let compressed = compress_to_bytes(12, infile, None).expect("failed to compress");
    let decompressed = decompress_to_bytes(&mut compressed.as_slice(), Some(compressed.len()))
        .expect("failed to decompress");

    let original = std::fs::read(filename).expect("failed to read infile");
    assert_eq!(original, decompressed)
}

#[test]
fn testinfilepress() {
    let filename = "./Cargo.lock";
    let file_bytes = std::fs::read(filename).expect("failed to read file");

    let file = std::fs::File::open(filename).expect("failed to open file");

    let mut cmp = Vec::<u8>::new();
    if let Err(err) = compress(12, file, &mut cmp) {
        panic!("got compression error: {:?}", err);
    };

    let mut decmp = Vec::<u8>::new();
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
    let filename = "./Cargo.lock";
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

    let tmp_file = std::fs::File::open(tmp_filename).expect("failed to re-open tmp_file");
    let compressed_len = tmp_file.metadata().expect("").len() as usize;
    let mut decmp = Vec::with_capacity(compressed_len);
    if let Err(err) = decompress(tmp_file, &mut decmp) {
        std::fs::remove_file(tmp_filename).expect("failed to remove tmp_file");
        panic!("failed to decompress tmp_file: {:?}", err)
    }
    decmp.truncate(decmp.len());

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
