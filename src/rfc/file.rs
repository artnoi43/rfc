use serde::{Deserialize, Serialize};

use super::Mode;

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub(crate) struct RfcFile {
    pub header: Header,
    pub data: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]

pub(crate) struct Header {
    mode: Mode,
    padding: Option<usize>,
    salt: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode;

    fn new_file() -> RfcFile {
        let content = include_str!("./file.rs").as_bytes().to_vec();
        let salt = "deadbeefbeefdead".as_bytes().to_vec();
        let padding = 16usize;

        let header = Header {
            mode: Mode::Aes256,
            padding: Some(padding),
            salt: Some(salt.clone()),
        };

        return RfcFile {
            header: header.clone(),
            data: content.clone(),
        };
    }

    #[test]
    fn test_serde() {
        let f = new_file();

        let bytes = bincode::serialize(&f).expect("failed to serialize");
        let decoded = bincode::deserialize::<RfcFile>(&bytes[..]).expect("failed to deserialize");
        assert_eq!(f.clone(), decoded);
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

        let f_bytes = bincode::serialize(&f).expect("failed to serialize");
        let f_no_padding_bytes = bincode::serialize(&f_no_padding).expect("failed to serialize");
        let f_no_salt_bytes = bincode::serialize(&f_no_salt).expect("failed to serialize");
        let f_no_header_bytes = bincode::serialize(&f_no_header).expect("failed to serialize");

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
        println!(
            "data_length: {}\nsize_of_padding: {}\nsize_of_header: {}\nf_bytes_length: {}\n",
            f.data.len(),
            std::mem::size_of::<usize>(),
            std::mem::size_of_val(&f.header),
            f_bytes.len(),
        );
    }
}
