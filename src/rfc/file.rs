use rkyv::ser::serializers::AllocSerializer;
use rkyv::validation::validators::DefaultValidator;
use rkyv::{Archive, Deserialize, Serialize};

use super::error::RfcError;

#[derive(Archive, Serialize, Deserialize, Clone, PartialEq, Debug)]
#[archive(check_bytes)]
pub(crate) struct RfcFile<H> {
    pub header: H,
    pub data: Vec<u8>,
}

impl<'a, H> RfcFile<H>
where
    H: Serialize<AllocSerializer<0>> + 'a,
    <H as Archive>::Archived:
        Deserialize<H, rkyv::Infallible> + rkyv::CheckBytes<DefaultValidator<'a>>,
{
    pub fn encode(&'a self) -> Result<Vec<u8>, RfcError> {
        rkyv::to_bytes(self)
            .map(|v| v.to_vec())
            .map_err(|err| RfcError::Deserialize(err.to_string()))
    }

    pub fn decode(bytes: &'a [u8]) -> Result<Self, RfcError> {
        let archived =
            rkyv::check_archived_root::<RfcFile<H>>(bytes).expect("failed to get archived value");

        archived
            .deserialize(&mut rkyv::Infallible)
            .map_err(|err| RfcError::Deserialize(err.to_string()))
    }
}
