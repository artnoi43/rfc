#![feature(array_chunks)]

mod cli;
mod rfc;

use clap::Parser;
use rpassword::read_password;

use rfc::buf::{open_file, read_file};
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
        &infile,
        infile_len,
        &mut open_file(args.outfile, true)?,
        args.encoding,
        args.compress,
    )?;

    Ok(())
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
