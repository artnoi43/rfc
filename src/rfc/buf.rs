use std::io::Write;

pub fn bytes_chunks<const BLOCK_SIZE: usize, T>(bytes: T) -> (Vec<[u8; BLOCK_SIZE]>, usize)
where
    T: AsRef<[u8]>,
{
    let chunks = {
        let len = bytes.as_ref().len();
        match len % BLOCK_SIZE {
            0 => len / BLOCK_SIZE,
            _ => len / BLOCK_SIZE + 1,
        }
    };

    let mut chunks: Vec<[u8; BLOCK_SIZE]> = Vec::with_capacity(chunks);

    let arrays = bytes.as_ref().array_chunks::<BLOCK_SIZE>();
    let remainder = arrays.remainder();

    for chunk in arrays {
        chunks.push(*chunk)
    }

    let to_pad = remainder.len();

    if to_pad != 0 {
        let mut chunk = [0u8; BLOCK_SIZE];
        fill(&mut chunk, remainder);

        chunks.push(chunk);
    }

    (chunks, to_pad)
}

// Fills buf with bytes
fn fill(mut buf: &mut [u8], bytes: &[u8]) {
    buf.write(bytes).expect("filling bytes failed");
}
