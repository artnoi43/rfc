use serde::{Deserialize, Serialize};

use super::error::RfcError;

// use super::{encoding::Encoding, Mode};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct RfcFile<H> {
    pub header: H,
    pub data: Vec<u8>,
}

impl<'a, H> RfcFile<H>
where
    H: Serialize + Deserialize<'a>,
{
    pub fn encode(&'a self) -> Result<Vec<u8>, RfcError> {
        bincode::serialize(&self).map_err(|err| {
            RfcError::Serialize(format!(
                "failed to serialize to bincode: {}",
                err.to_string()
            ))
        })
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, RfcError> {
        bincode::deserialize(bytes.as_ref()).map_err(|err| {
            RfcError::Deserialize(format!(
                "failed to serialize to bincode: {}",
                err.to_string()
            ))
        })
    }
}
