#![feature(array_chunks)]

mod cli;
mod error;

use std::io::Write;

// TODO: Use AEAD
use aes::cipher::{generic_array::GenericArray, typenum::U16};
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use clap::Parser;

use cli::{Args, KeyType};

fn main() {
    // Parse CLI arguments and read infile
    let args = Args::parse();

    // Prepare key
    let key = match args.key_type {
        KeyType::Passphrase => key_bytes(get_passphrase().expect("failed to read passphrase"))
            .expect("failed to get passphrase bytes"),
        KeyType::KeyFile => key_bytes("this is my key").expect("failed to get key bytes"),
    };

    // Read bytes from infile
    let bytes = read_file(&args.filename).unwrap();
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

fn get_passphrase() -> std::io::Result<String> {
    println!("Enter your password:");

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;

    Ok(line)
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
