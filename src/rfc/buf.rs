use std::io::{Read, Write};

use super::error::RfcError;

/// Returns a new array of generic size `BLOCK_SIZE`, as well as the remainder that did not
/// fit into a full chunk of `BLOCK_SIZE`.
///
/// The last remainder block is padded with 0s if not full.
pub fn bytes_chunks<const BLOCK_SIZE: usize, T>(bytes: T) -> (Vec<[u8; BLOCK_SIZE]>, usize)
where
    T: AsRef<[u8]>,
{
    let chunks = {
        let len = bytes.as_ref().len();
        match len % BLOCK_SIZE {
            0 => len / BLOCK_SIZE,
            _ => len / BLOCK_SIZE + 1,
        }
    };

    let mut chunks: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(chunks);

    let arrays = bytes.as_ref().array_chunks::<BLOCK_SIZE>();
    let remainder = arrays.remainder();

    for chunk in arrays {
        chunks.push(*chunk)
    }

    if !remainder.is_empty() {
        let mut chunk = [0u8; BLOCK_SIZE];
        fill(&mut chunk, remainder);

        chunks.push(chunk);
    }

    (chunks, remainder.len())
}

/// Reads all bytes from `reader` into a new byte vector.
pub fn read_bytes<R>(mut reader: R, prealloc: Option<usize>) -> Result<Vec<u8>, RfcError>
where
    R: Read,
{
    let mut buf = Vec::with_capacity(prealloc.unwrap_or(0));
    let _written = reader
        .read_to_end(&mut buf)
        .map_err(|err| RfcError::IoError(err))?;

    buf.truncate(buf.len());
    Ok(buf)
}

#[test]
fn test_read_bytes() {
    let bytes = include_bytes!("../../Cargo.lock").to_vec();
    for i in 0..bytes.len() + 10 {
        let buf = read_bytes(&mut bytes.as_slice(), Some(i)).unwrap();
        assert_eq!(bytes.len(), buf.len());
        assert_eq!(bytes, buf);
    }
}

pub fn write_to_writer<W, T>(mut writer: W, data: T) -> Result<(), RfcError>
where
    W: Write,
    T: AsRef<[u8]>,
{
    let _ = writer
        .write_all(data.as_ref())
        .map_err(|err| RfcError::IoError(err));

    Ok(())
}

pub fn write_bytes<W, T>(mut w: W, data: T) -> Result<usize, RfcError>
where
    W: Write,
    T: AsRef<[u8]>,
{
    w.write(data.as_ref()).map_err(|err| RfcError::IoError(err))
}

// Fills buf with bytes
pub fn fill(mut buf: &mut [u8], bytes: &[u8]) {
    buf.write(bytes).expect("filling bytes failed");
}

pub fn read_file<P>(filename: P) -> Result<Vec<u8>, RfcError>
where
    P: AsRef<std::path::Path>,
{
    std::fs::read(filename).map_err(|err| RfcError::IoError(err))
}

pub fn open_file<P>(filename: P, write: bool) -> Result<std::fs::File, RfcError>
where
    P: AsRef<std::path::Path>,
{
    std::fs::OpenOptions::new()
        .create(write)
        .write(write)
        .read(true)
        .open(filename)
        .map_err(|err| RfcError::IoError(err))
}

#[test]
fn test_open_file() {
    vec!["./Cargo.toml", "./Cargo.lock"]
        .into_iter()
        .for_each(|filename| {
            assert!(open_file(filename, true).is_ok());
            assert!(open_file(filename, false).is_ok());
        })
}
