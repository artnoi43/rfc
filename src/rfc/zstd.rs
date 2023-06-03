// use std::io;

// // This function use the convenient `copy_encode` method
// pub fn compress(level: i32) {
//     zstd::stream::copy_encode(io::stdin(), io::stdout(), level).unwrap();
// }

// // This function does the same thing, directly using an `Encoder`:
// pub fn compress_manually(level: i32) {
//     let mut encoder = zstd::stream::Encoder::new(io::stdout(), level).unwrap();
//     io::copy(&mut io::stdin(), &mut encoder).unwrap();
//     encoder.finish().unwrap();
// }

// pub fn decompress() {
//     zstd::stream::copy_decode(io::stdin(), io::stdout()).unwrap();
// }

#[derive(Clone, Copy, Debug)]
pub struct Level(pub Option<i32>);
impl std::fmt::Display for Level {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(level) => write!(f, "{}", level.to_string()),
            None => write!(f, ""),
        }
    }
}
