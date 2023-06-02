use rkyv::ser::serializers::AllocSerializer;
use rkyv::validation::validators::DefaultValidator;

use super::error::RfcError;

/// RfcFile is for some ciphers that need to store metadata
/// in addition to ciphertext. Ciphers that need the metadata
/// have to implement their own header H and return only the
/// bytes back to rfc module.
#[derive(
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    serde::Serialize,
    serde::Deserialize,
    Clone,
    PartialEq,
    Debug,
)]
#[archive(check_bytes)]
pub(crate) struct RfcFile<H>(pub H, pub Vec<u8>);

impl<'a, H> RfcFile<H>
where
    H: rkyv::Serialize<AllocSerializer<0>> + 'a,
    <H as rkyv::Archive>::Archived:
        rkyv::Deserialize<H, rkyv::Infallible> + rkyv::CheckBytes<DefaultValidator<'a>>,
{
    pub fn encode(&'a self) -> Result<Vec<u8>, RfcError> {
        rkyv::to_bytes(self)
            .map(|v| v.to_vec())
            .map_err(|err| RfcError::Deserialize(err.to_string()))
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, RfcError> {
        use rkyv::Deserialize;

        let archived =
            rkyv::check_archived_root::<RfcFile<H>>(bytes).expect("failed to get archived value");

        archived
            .deserialize(&mut rkyv::Infallible)
            .map_err(|err| RfcError::Deserialize(err.to_string()))
    }
}

impl<'a, H> RfcFile<H>
where
    H: serde::Serialize + serde::Deserialize<'a>,
{
    pub fn to_bincode(&'a self) -> Result<Vec<u8>, RfcError> {
        bincode::serialize(self)
            .map_err(|err| RfcError::Serialize(format!("failed to serialize with serde: {}", err)))
    }

    pub fn from_bincode(bytes: &'a [u8]) -> Result<Self, RfcError> {
        bincode::deserialize(bytes.as_ref()).map_err(|err| {
            RfcError::Deserialize(format!(
                "failed to serialize to bincode: {}",
                err.to_string()
            ))
        })
    }

    pub fn to_json(&'a self) -> Result<Vec<u8>, RfcError> {
        serde_json::to_vec(self)
            .map_err(|err| RfcError::Serialize(format!("failed to serialize to JSON: {}", err)))
    }

    pub fn from_json(json: &'a [u8]) -> Result<Self, RfcError> {
        serde_json::from_slice(json).map_err(|err| {
            RfcError::Deserialize(format!("failed to deserialize from JSON: {}", err))
        })
    }
}
