pub fn bytes_to_blocks<B: AsRef<[u8]>>(bytes: B) -> Vec<[u8; 16]> {
    let mut vecs: Vec<[u8; 16]> = Vec::with_capacity(bytes.as_ref().len() / 16);

    for chunk in bytes.as_ref().array_chunks::<16>() {
        vecs.push(*chunk)
    }

    vecs
}
