use serde::{Deserialize, Serialize};

use super::error::RfcError;

// use super::{encoding::Encoding, Mode};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct RfcFile {
    pub header: Header,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]

pub(crate) struct Header {
    // pub mode: Mode,
    // pub encoding: Encoding,
    pub padding: Option<usize>,
    pub salt: Option<Vec<u8>>,
}

impl RfcFile {
    pub fn encode(&self) -> Result<Vec<u8>, RfcError> {
        bincode::serialize(&self).map_err(|err| {
            RfcError::Serialize(format!(
                "failed to serialize to bincode: {}",
                err.to_string()
            ))
        })
    }

    pub fn decode<T>(bytes: T) -> Result<Self, RfcError>
    where
        T: AsRef<[u8]>,
    {
        bincode::deserialize(bytes.as_ref()).map_err(|err| {
            RfcError::Deserialize(format!(
                "failed to serialize to bincode: {}",
                err.to_string()
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_file() -> RfcFile {
        let content = include_str!("./file.rs").as_bytes().to_vec();
        let salt = "deadbeefbeefdead".as_bytes().to_vec();
        let padding = 16usize;

        let header = Header {
            // mode: Mode::Aes256,
            // encoding: Encoding::Plain,
            padding: Some(padding),
            salt: Some(salt.clone()),
        };

        return RfcFile {
            header,
            data: content,
        };
    }

    #[test]
    fn test_serde() {
        let f = new_file();

        let bytes = f.encode().expect("failed to encode");
        let decoded = RfcFile::decode(&bytes[..]).expect("failed to deserialize");
        assert_eq!(f, decoded);
    }

    #[test]
    fn cmp_sizes() {
        let f = new_file();

        let f_no_padding = RfcFile {
            header: Header {
                padding: None,
                ..f.header.clone()
            },
            ..f.clone()
        };

        let f_no_salt = RfcFile {
            header: Header {
                salt: None,
                ..f.header.clone()
            },
            ..f.clone()
        };

        let f_no_header = RfcFile {
            header: Header {
                padding: None,
                salt: None,
                ..f.header.clone()
            },
            ..f.clone()
        };

        let f_bytes = f.encode().expect("failed to encode");
        let f_no_padding_bytes = f_no_padding.encode().expect("failed to encode");
        let f_no_salt_bytes = f_no_salt.encode().expect("failed to encode");
        let f_no_header_bytes = f_no_header.encode().expect("failed to encode");

        println!("full header");
        print_size(&f, f_bytes);
        println!("no padding");
        print_size(&f, f_no_padding_bytes);
        println!("no salt");
        print_size(&f, f_no_salt_bytes);
        println!("no header");
        print_size(&f_no_header, f_no_header_bytes);
    }

    fn print_size(f: &RfcFile, f_bytes: Vec<u8>) {
        let data_len = f.data.len();
        let bytes_len = f_bytes.len();
        let header_size = bytes_len - data_len;

        println!(
            "size_of_data: {}\nmem_size_of_padding: {}\nmem_size_of_header: {}\nfile_bytes_length: {}\nheader_bytes: {}\n",
            f.data.len(),
            std::mem::size_of::<usize>(),
            std::mem::size_of_val(&f.header),
            f_bytes.len(),
            header_size,
        );
    }
}
