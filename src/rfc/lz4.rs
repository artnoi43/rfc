use lz4_flex;

use std::io::{self, Read, Write};

use super::error::RfcError;

pub fn compress_bytes<T>(bytes: T) -> Vec<u8>
where
    T: AsRef<[u8]>,
{
    lz4_flex::compress(bytes.as_ref())
}

/// Pre-allocates a buffer with capacity `prealloc` if any,
/// and compresses data from `from` into the buffer,
/// truncating any buffer extra capacity before returning the buffer.
pub fn compress_to_bytes_sized<R>(from: R, prealloc: Option<usize>) -> Result<Vec<u8>, RfcError>
where
    R: Read,
{
    let mut buf = Vec::with_capacity(prealloc.unwrap_or(0));
    compress_reader_to_writer(from, &mut buf)?;

    buf.truncate(buf.len());
    Ok(buf)
}

/// Pre-allocates a buffer with capacity `prealloc` if any,
/// and decompresses data from `from` into the buffer
/// truncating any buffer extra capacity before returning the buffer.
pub fn decompress_to_bytes_sized<R>(
    mut from: R,
    prealloc: Option<usize>,
) -> Result<Vec<u8>, RfcError>
where
    R: Read,
{
    let mut buf = Vec::with_capacity(prealloc.unwrap_or(0));
    decompress_reader_to_writer(&mut from, &mut buf)?;

    buf.truncate(buf.len());
    Ok(buf)
}

/// Reads bytes from Reader `from` and compresses using level. Output is written to Writer `to`.
pub fn compress_reader_to_writer<R, W>(mut from: R, to: W) -> Result<usize, RfcError>
where
    R: Read,
    W: Write,
{
    let mut compressor = lz4_flex::frame::FrameEncoder::new(to);

    let written =
        io::copy(&mut from, &mut compressor).map_err(|err| RfcError::IoError(err.into()))?;

    compressor
        .finish()
        .map_err(|err| RfcError::IoError(err.into()))?;

    Ok(written as usize)
}

/// Decompresses from Reader `r` to Writer `w`
pub fn decompress_reader_to_writer<R, W>(r: R, mut w: W) -> Result<usize, RfcError>
where
    R: Read,
    W: Write,
{
    let mut decompressor = lz4_flex::frame::FrameDecoder::new(r);
    let written = io::copy(&mut decompressor, &mut w).map_err(|err| RfcError::IoError(err))?;

    Ok(written as usize)
}

#[test]
fn test_compress_bytes() {
    let filename = "./Cargo.lock";

    let infile = std::fs::File::open(filename).expect("failed to open infile");

    let compressed = compress_to_bytes_sized(infile, None).expect("failed to compress");
    let decompressed =
        decompress_to_bytes_sized(&mut compressed.as_slice(), Some(compressed.len()))
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
    if let Err(err) = compress_reader_to_writer(file, &mut cmp) {
        panic!("got compression error: {:?}", err);
    };

    let mut decmp = Vec::<u8>::new();
    if let Err(err) = decompress_reader_to_writer(&mut cmp.as_slice(), &mut decmp) {
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

    if let Err(err) = compress_reader_to_writer(infile, &tmp_file) {
        std::fs::remove_file(tmp_filename).expect("failed to remove tmp_file");
        panic!("failed to compress to tmp_file: {:?}", err);
    }

    let tmp_file = std::fs::File::open(tmp_filename).expect("failed to re-open tmp_file");
    let compressed_len = tmp_file.metadata().expect("").len() as usize;
    let mut decmp = Vec::with_capacity(compressed_len);
    if let Err(err) = decompress_reader_to_writer(tmp_file, &mut decmp) {
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
