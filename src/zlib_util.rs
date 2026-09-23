//! Single-stream zlib inflation with explicit stream-boundary detection.
//!
//! Pack entries are concatenated zlib streams, so we must know exactly where a
//! stream ends: we use a `zng`-style fixed-size output loop and read
//! `total_in` once the stream reports Z_STREAM_END, which simultaneously proves
//! the Adler-32 checksum was verified.

use flate2::{Decompress, FlushDecompress};

#[derive(Debug, Clone)]
pub struct Inflated {
    pub data: Vec<u8>,
    pub compressed_len: usize,
    pub adler_ok: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InflateError {
    /// Not a zlib stream / corrupted header or data before stream end.
    Corrupt(String),
    /// Decompressed more than `max_output` bytes (decompression bomb /
    /// truncated mid-stream once the lie becomes visible).
    ExceedsMaxOutput { produced: usize },
}

/// Inflate exactly one zlib stream beginning at `input[0]`.
pub fn inflate_one(input: &[u8], max_output: usize) -> Result<Inflated, InflateError> {
    let mut decomp = Decompress::new(true);
    let mut out = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    let mut input_pos = 0usize;
    loop {
        let before_in = decomp.total_in();
        let before_out = decomp.total_out();
        let in_slice = &input[input_pos.min(input.len())..];
        let res = decomp.decompress(in_slice, &mut buf, FlushDecompress::None);
        let consumed = (decomp.total_in() - before_in) as usize;
        let produced = (decomp.total_out() - before_out) as usize;
        input_pos += consumed;
        out.extend_from_slice(&buf[..produced]);
        match res {
            Ok(flate2::Status::StreamEnd) => {
                return Ok(Inflated {
                    data: out,
                    compressed_len: decomp.total_in() as usize,
                    adler_ok: true,
                });
            }
            Ok(flate2::Status::Ok) => {
                if out.len() > max_output {
                    return Err(InflateError::ExceedsMaxOutput {
                        produced: out.len(),
                    });
                }
                // No progress at all -> corrupt/truncated stream.
                if consumed == 0 && produced == 0 {
                    return Err(InflateError::Corrupt("no progress".into()));
                }
            }
            Err(e) => return Err(InflateError::Corrupt(e.to_string())),
            Ok(flate2::Status::BufError) => {
                // Should not happen with None flush; treat as corrupt.
                return Err(InflateError::Corrupt("buf error".into()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    #[test]
    fn boundary_detection_with_trailing_bytes() {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"hello pack world").unwrap();
        let mut data = enc.finish().unwrap();
        let trailing_len = data.len();
        data.extend_from_slice(b"NEXT_ENTRY_BYTES");
        let r = inflate_one(&data, 1 << 20).unwrap();
        assert_eq!(r.data, b"hello pack world");
        assert_eq!(r.compressed_len, trailing_len);
        assert!(r.adler_ok);
    }

    #[test]
    fn bomb_cap() {
        let zeroes = vec![0u8; 4096];
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&zeroes).unwrap();
        let data = enc.finish().unwrap();
        assert!(matches!(
            inflate_one(&data, 100),
            Err(InflateError::ExceedsMaxOutput { .. })
        ));
    }
}
