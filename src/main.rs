#![feature(array_chunks)]

mod cli;
mod rfc;

use clap::Parser;
use rpassword::read_password;

fn main() {
    // Parse CLI arguments and read infile
    let args = cli::Args::parse();

    // Prepare key
    let key = get_key(args.key_type, args.key_file).expect("failed to get encryption key");
    // Read bytes from infile
    let mut bytes = read_file(&args.filename).expect("failed to read infile");

    bytes = rfc::pre_process(bytes, args.decrypt, args.encoding);
    bytes = rfc::crypt(bytes, args.decrypt, key, rfc::Mode::Aes256);
    bytes = rfc::post_process(bytes, args.decrypt, args.encoding);

    if let Err(err) = write_out(args.outfile, &bytes) {
        eprintln!("failed to write output to stdout: {}", err)
    }
}

fn read_file<P>(filename: P) -> std::io::Result<Vec<u8>>
where
    P: AsRef<std::path::Path>,
{
    std::fs::read(filename)
}

fn get_passphrase<'a>() -> std::io::Result<Vec<u8>> {
    println!("Enter your passphrase (will not echo):");
    let passphrase = read_password()?;

    Ok(passphrase.as_bytes().to_owned())
}

fn get_key<P>(key_type: cli::KeyType, key_file: Option<P>) -> std::io::Result<Vec<u8>>
where
    P: AsRef<std::path::Path>,
{
    let key = match key_type {
        cli::KeyType::Passphrase => get_passphrase().expect("failed to read passphrase"),
        cli::KeyType::KeyFile => {
            read_file(key_file.expect("no keyfile specified")).expect("failed to read key file")
        }
    };

    Ok(key)
}

pub fn bytes_chunks<B: AsRef<[u8]>, const BLOCKSIZE: usize>(bytes: B) -> Vec<[u8; BLOCKSIZE]> {
    let mut vecs: Vec<[u8; BLOCKSIZE]> = Vec::with_capacity(bytes.as_ref().len() / BLOCKSIZE);

    for chunk in bytes.as_ref().array_chunks::<BLOCKSIZE>() {
        vecs.push(*chunk)
    }

    vecs
}

fn write_out<P, T>(outfile: P, data: T) -> std::io::Result<()>
where
    P: AsRef<std::path::Path>,
    T: AsRef<[u8]>,
{
    std::fs::write(outfile, data.as_ref())
}
