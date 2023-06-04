use base64::{self, engine::general_purpose::STANDARD as b64_engine};

use std::io::{Read, Write};

use crate::rfc::error::RfcError;

pub fn encode_b64<S, D>(src: &mut S, dst: &mut D) -> Result<(), RfcError>
where
    S: Read,
    D: Write,
{
    let mut encoder = base64::write::EncoderWriter::new(dst, &b64_engine);

    std::io::copy(src, &mut encoder).map_err(|err| RfcError::IoError(err))?;

    Ok(())
}

pub fn decode_b64<S, D>(src: &mut S, dst: &mut D) -> Result<(), RfcError>
where
    S: Read,
    D: Write,
{
    let mut decoder = base64::read::DecoderReader::new(src, &b64_engine);

    std::io::copy(&mut decoder, dst).map_err(|err| RfcError::IoError(err))?;

    Ok(())
}

pub fn prealloc_size_b64(len: usize) -> usize {
    len * 4 / 3 + 4
}

#[test]
fn test_b64() {
    let filename = "./Cargo.toml";
    let mut infile = std::fs::File::open(filename).unwrap();
    let infile_len = infile.metadata().unwrap().len() as usize;
    let mut encoded = Vec::with_capacity(prealloc_size_b64(infile_len));
    let mut decoded = Vec::with_capacity(infile_len);

    encode_b64(&mut infile, &mut encoded).unwrap();
    decode_b64(&mut encoded.as_slice(), &mut decoded).unwrap();

    let original_bytes = std::fs::read(filename).unwrap();

    assert_eq!(original_bytes, decoded);
}
