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

pub(crate) struct HeaderAes(pub usize);

#[cfg(test)]
mod tests {
    use rkyv::Deserialize;

    use super::*;
    use crate::rfc::wrapper::WrapperBytes;

    #[test]
    fn test_rkyv_aes_header() {
        use rkyv::Deserialize;

        let val = HeaderAes(0);

        let bytes = rkyv::to_bytes::<HeaderAes, 16>(&val).unwrap();
        let archived =
            rkyv::check_archived_root::<HeaderAes>(&bytes[..]).expect("failed to archive");
        let deserialized: HeaderAes = archived
            .deserialize(&mut rkyv::Infallible)
            .expect("failed to deserialize");

        println!("bytes: {}", bytes.len());
        assert_eq!(val, deserialized);
    }

    fn new_file() -> WrapperBytes<HeaderAes> {
        let content = include_str!("./header.rs").as_bytes().to_vec();
        let extra = 16usize;

        let header = HeaderAes(extra);

        return WrapperBytes(header, content);
    }

    #[test]
    fn test_serde() {
        let f = new_file();

        let bytes = f.encode().expect("failed to encode");
        let decoded = WrapperBytes::decode_archived(&bytes[..]).expect("failed to deserialize");
        assert_eq!(
            f,
            decoded
                .deserialize(&mut rkyv::Infallible)
                .expect("failed to deserialize")
        );
    }

    #[test]
    fn cmp_sizes() {
        let f = new_file();
        let f_no_padding = WrapperBytes(HeaderAes(0), f.1.clone());
        let f_no_salt = WrapperBytes(HeaderAes(0), f.1.clone());

        print_file("full header", &f);
        print_file("no padding", &f_no_padding);
        print_file("no salt", &f_no_salt);
    }

    fn print_file(filename: &str, file: &WrapperBytes<HeaderAes>) {
        print_size(
            format!("rkyv {}", filename),
            file,
            file.encode().expect("failed to encode rkyv"),
        );

        print_size(
            format!("bincode {}", filename),
            file,
            file.to_bincode().expect("failed to encode rkyv"),
        );

        print_size(
            format!("json {}", filename),
            file,
            file.to_json().expect("failed to encode rkyv"),
        );
    }

    fn print_size(s: String, f: &WrapperBytes<HeaderAes>, f_bytes: Vec<u8>) {
        println!("{}", s);

        let (header, data) = (&f.0, &f.1);

        let data_len = data.len();
        let bytes_len = f_bytes.len();
        let header_size = bytes_len - data_len;

        println!(
            "size_of_data: {}\nmem_size_of_padding: {}\nmem_size_of_header: {}\nheader_bytes: {}\nfile_bytes_length: {}\n",
            data.len(),
            std::mem::size_of::<usize>(),
            std::mem::size_of_val(&header),
            header_size,
            f_bytes.len(),
        );
    }
}
