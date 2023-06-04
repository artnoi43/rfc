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
pub fn from_reader<R>(mut reader: R, prealloc: Option<usize>) -> Result<Vec<u8>, RfcError>
where
    R: Read,
{
    let mut buf = Vec::with_capacity(prealloc.unwrap_or(0));
    reader
        .read_to_end(&mut buf)
        .map_err(|err| RfcError::IoError(err))?;

    buf.truncate(buf.len());
    Ok(buf)
}

// Fills buf with bytes
fn fill(mut buf: &mut [u8], bytes: &[u8]) {
    buf.write(bytes).expect("filling bytes failed");
}
