#![feature(array_chunks)]

mod cli;
mod error;
mod rfc;

use std::io::Write;

// TODO: Use AEAD
use aes::cipher::{generic_array::GenericArray, typenum::U16};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use clap::Parser;
use rpassword::read_password;

fn main() {
    // Parse CLI arguments and read infile
    let args = cli::Args::parse();

    // Prepare key
    let key = get_key(args.key_type, args.key_file).expect("failed to get encryption key");
    // Read bytes from infile
    let bytes = read_file(&args.filename).expect("failed to read infile");
    // Chunk file bytes into block sized chunks.
    let bytes = aes_blocks(bytes);

    // Prepare AES blocks
    let mut blocks: Vec<GenericArray<u8, U16>> = Vec::with_capacity(bytes.len());
    for block in bytes {
        blocks.push(GenericArray::from(block));
    }

    // Prepare cipher
    let cipher = Aes256::new(&GenericArray::from(key));

    match args.decrypt {
        false => cipher.encrypt_blocks(&mut blocks),
        true => cipher.decrypt_blocks(&mut blocks),
    }

    let blocks = blocks
        .into_iter()
        .map(|block| block.as_slice().to_owned())
        .flat_map(|slice| slice.into_iter().map(|byte| byte.to_owned()))
        .collect::<Vec<_>>();

    if let Err(err) = write_out(args.outfile, &blocks) {
        eprintln!("failed to write output to stdout: {}", err)
    }
}

fn read_file<P: AsRef<std::path::Path>>(filename: P) -> std::io::Result<Vec<u8>> {
    std::fs::read(filename)
}

fn get_passphrase<'a>() -> std::io::Result<Vec<u8>> {
    println!("Enter your passphrase (will not echo):");
    let passphrase = read_password()?;

    Ok(passphrase.as_bytes().to_owned())
}

fn get_key<P: AsRef<std::path::Path>>(
    key_type: cli::KeyType,
    key_file: Option<P>,
) -> std::io::Result<[u8; 32]> {
    let key = match key_type {
        cli::KeyType::Passphrase => get_passphrase().expect("failed to read passphrase"),
        cli::KeyType::KeyFile => {
            read_file(key_file.expect("no keyfile specified")).expect("failed to read key file")
        }
    };

    key_bytes(key)
}

fn key_bytes<K: AsRef<[u8]>>(key: K) -> std::io::Result<[u8; 32]> {
    let mut bytes = [0u8; 32];
    let mut buf = &mut bytes[..];

    buf.write_all(key.as_ref())?;
    Ok(bytes)
}

fn aes_blocks<B: AsRef<[u8]>>(bytes: B) -> Vec<[u8; 16]> {
    let mut vecs: Vec<[u8; 16]> = Vec::with_capacity(bytes.as_ref().len() / 16);

    for chunk in bytes.as_ref().array_chunks::<16>() {
        vecs.push(*chunk)
    }

    vecs
}

fn write_out<P: AsRef<std::path::Path>, B: AsRef<[u8]>>(
    outfile: P,
    data: B,
) -> std::io::Result<()> {
    std::fs::write(outfile, data.as_ref())
}
