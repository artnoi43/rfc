use hex;

use crate::rfc::error::RfcError;

pub fn encode_hex<T>(plain: T) -> Vec<u8>
where
    T: AsRef<[u8]>,
{
    hex::encode(plain).as_bytes().to_vec()
}

pub fn decode_hex<T>(hex_data: T) -> Result<Vec<u8>, RfcError>
where
    T: AsRef<[u8]>,
{
    hex::decode(hex_data).map_err(|err| RfcError::Encoding(err.to_string()))
}
