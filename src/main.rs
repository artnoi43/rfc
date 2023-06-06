#![feature(array_chunks)]

mod cli;
mod rfc;

use clap::Parser;
use rpassword::read_password;

use rfc::error::RfcError;

fn main() -> Result<(), RfcError> {
    let args = cli::Args::parse();
    // Prepare key
    let key = get_key(args.key_type, args.key_file)?;

    // Read bytes from infile
    let infile = open_file(args.filename, true)?;

    let infile_len = Some(
        infile
            .metadata()
            .map_err(|err| RfcError::IoError(err))?
            .len() as usize,
    );

    let _ = rfc::core(
        args.decrypt,
        key,
        args.cipher.rfc_mode(),
        infile,
        infile_len,
        &mut open_file(args.outfile, true)?,
        args.encoding,
        args.compress,
    )?;

    Ok(())
}

fn read_file<P>(filename: P) -> Result<Vec<u8>, RfcError>
where
    P: AsRef<std::path::Path>,
{
    std::fs::read(filename).map_err(|err| RfcError::IoError(err))
}

fn open_file<P>(filename: P, write: bool) -> Result<std::fs::File, RfcError>
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

fn get_passphrase<'a>() -> Result<Vec<u8>, RfcError> {
    println!("Enter your passphrase (will not echo):");
    let passphrase = read_password().map_err(|err| RfcError::IoError(err))?;

    Ok(passphrase.as_bytes().to_vec())
}

fn get_key<P>(key_type: cli::KeyType, key_file: Option<P>) -> Result<Vec<u8>, RfcError>
where
    P: AsRef<std::path::Path>,
{
    match key_type {
        cli::KeyType::Passphrase => get_passphrase(),
        cli::KeyType::KeyFile => read_file(key_file.expect("missing key filename")),
    }
}
