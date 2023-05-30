mod aes;

use crate::cli;

pub fn bytes_to_blocks<B: AsRef<[u8]>, const BlockSize: usize>(bytes: B) -> Vec<[u8; BlockSize]> {
    let mut vecs: Vec<[u8; BlockSize]> = Vec::with_capacity(bytes.as_ref().len() / BlockSize);

    for chunk in bytes.as_ref().array_chunks::<BlockSize>() {
        vecs.push(*chunk)
    }

    vecs
}

fn pre_process(decrypt: bool, codec: cli::Encoding) {}
