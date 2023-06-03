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
    let infile = open_file(args.filename, false)?;
    let infile_len = Some(
        infile
            .metadata()
            .map_err(|err| RfcError::IoError(err))?
            .len() as usize,
    );

    // Pre-processes file bytes, e.g. decompress or decode
    let bytes = rfc::pre_process(
        args.decrypt,
        infile,
        infile_len,
        args.encoding,
        args.compress,
    )
    .expect("pre_process failed");

    // Performs encryption or decryption
    let bytes = rfc::crypt(args.decrypt, bytes, key, args.cipher.rfc_mode())?;
    // Post-processes output bytes, e.g. compress or encode
    rfc::post_process_and_write_out(
        args.decrypt,
        bytes,
        args.encoding,
        args.compress,
        open_file(args.outfile, true)?,
    )
    .expect("post_process failed");

    Ok(())
}

fn read_file<P>(filename: P) -> Result<Vec<u8>, RfcError>
where
    P: AsRef<std::path::Path>,
{
    std::fs::read(filename).map_err(|err| RfcError::IoError(err))
}

fn open_file<P>(filename: P, w: bool) -> Result<std::fs::File, RfcError>
where
    P: AsRef<std::path::Path>,
{
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(w)
        .open(filename)
        .map_err(|err| RfcError::IoError(err))
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
