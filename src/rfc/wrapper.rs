use rkyv::ser::serializers::AllocSerializer;
use rkyv::validation::validators::DefaultValidator;

use super::error::RfcError;

/// WrapperBytes wraps a byte vector with `H` in a tuple.
/// This allows us to store metadata in addition to the ciphertext,
/// like salt. This also allows ciphers to wrap their own metadata
/// before passing serializing their ciphertext plus metadata back
/// as `Vec<u8>` to rfc.
#[derive(
    Clone,
    PartialEq,
    Debug,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
    serde::Serialize,
    serde::Deserialize,
)]
#[archive(check_bytes)]
pub struct WrapperBytes<H>(pub H, pub Vec<u8>);

/// Methods using `rkyv`.
impl<'a, H> WrapperBytes<H>
where
    H: rkyv::Serialize<AllocSerializer<0>> + 'a,
    <H as rkyv::Archive>::Archived:
        rkyv::Deserialize<H, rkyv::Infallible> + rkyv::CheckBytes<DefaultValidator<'a>>,
{
    /// Encodes to bytes using `rkyv`.
    pub fn encode(&'a self) -> Result<Vec<u8>, RfcError> {
        rkyv::to_bytes(self)
            .map(|v| v.to_vec())
            .map_err(|err| RfcError::Deserialize(err.to_string()))
    }

    /// Returns the archived form of Self from the given slice of bytes, with zero-copy.
    pub fn decode_archived(bytes: &'a [u8]) -> Result<&ArchivedWrapperBytes<H>, RfcError> {
        rkyv::check_archived_root::<Self>(bytes)
            .map_err(|err| RfcError::Deserialize(format!("failed to get archived form: {}", err)))
    }

    /// Returns a new Self parsed from the archived form.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, RfcError> {
        use rkyv::Deserialize;

        Self::decode_archived(bytes)?
            .deserialize(&mut rkyv::Infallible)
            .map_err(|err| RfcError::Deserialize(err.to_string()))
    }
}

/// Methods using `serde` traits.
impl<'a, H> WrapperBytes<H>
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

#[test]
fn test_decode_archived() {
    let h = b"header_bytes".to_vec();
    let d = b"data_bytes".to_vec();

    let w = WrapperBytes::<Vec<u8>>(h.clone(), d.clone())
        .encode()
        .expect("failed to encode");

    let archived = WrapperBytes::<Vec<u8>>::decode_archived(&w).expect("failed to decode_archived");

    assert_eq!(h, archived.0.to_vec());
    assert_eq!(d, archived.1.to_vec());
}
