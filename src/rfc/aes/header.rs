use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]

pub(crate) struct HeaderAes {
    // pub mode: Mode,
    // pub encoding: Encoding,
    pub padding: usize,
    pub salt: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc::file::RfcFile;

    fn new_file() -> RfcFile<HeaderAes> {
        let content = include_str!("./header.rs").as_bytes().to_vec();
        let salt = "deadbeefbeefdead".as_bytes().to_vec();
        let padding = 16usize;

        let header = HeaderAes {
            // mode: Mode::Aes256,
            // encoding: Encoding::Plain,
            padding: padding,
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
            header: HeaderAes {
                padding: 0,
                ..f.header.clone()
            },
            ..f.clone()
        };

        let f_no_salt = RfcFile {
            header: HeaderAes {
                salt: None,
                ..f.header.clone()
            },
            ..f.clone()
        };

        let f_no_header = RfcFile {
            header: HeaderAes {
                padding: 0,
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

    fn print_size(f: &RfcFile<HeaderAes>, f_bytes: Vec<u8>) {
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
