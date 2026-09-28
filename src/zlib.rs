//! zlib (RFC1950) inflate with precise compressed-byte boundary accounting.
//!
//! Git pack/loose objects store raw DEFLATE inside a zlib wrapper. We must know
//! exactly how many compressed bytes were consumed so that the sequential pack
//! scanner can move to the next object and so we can detect a *size lie*: a
//! header that promises N bytes while the stream actually contains M.

use crate::error::{Error, Result};
use flate2::{Decompress, FlushDecompress};

#[derive(Debug)]
pub struct Inflate {
    /// Decompressed bytes (capped at `hard_cap + 1`; see [`inflate`]).
    pub data: Vec<u8>,
    /// Number of compressed input bytes consumed up to and including the
    /// final stored block of the zlib stream.
    pub consumed: usize,
    /// True if the stream ended cleanly (`StreamEnd` reached).
    pub finished: bool,
    /// True if output exceeded `hard_cap` (one guard byte is retained).
    pub over_cap: bool,
}

/// Inflate a zlib stream beginning at `src[start..]`.
///
/// `hard_cap` bounds memory use. If more than `hard_cap` output bytes appear,
/// decompression stops, `over_cap` is set and one extra guard byte is kept.
pub fn inflate(src: &[u8], start: usize, hard_cap: usize) -> Result<Inflate> {
    let input = &src[start..];
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 32 * 1024];

    loop {
        let res = d.decompress(&input[d.total_in() as usize..], &mut tmp, FlushDecompress::None);
        let n = (d.total_out() as usize).saturating_sub(out.len());
        out.extend_from_slice(&tmp[..n.min(tmp.len())]);

        if out.len() > hard_cap {
            out.truncate(hard_cap + 1);
            return Ok(Inflate {
                data: out,
                consumed: d.total_in() as usize,
                finished: false,
                over_cap: true,
            });
        }

        match res {
            Ok(flate2::Status::StreamEnd) => {
                return Ok(Inflate {
                    data: out,
                    consumed: d.total_in() as usize,
                    finished: true,
                    over_cap: false,
                });
            }
            Ok(flate2::Status::Ok | flate2::Status::BufError) => {
                // No input left and stream never terminated => truncated.
                if d.total_in() as usize >= input.len() {
                    return Err(Error::Zlib("truncated zlib stream (input exhausted)".into()));
                }
            }
            Err(e) => return Err(Error::Zlib(e.to_string())),
        }
    }
}

/// Convenience: inflate a whole standalone buffer (loose objects).
pub fn inflate_all(src: &[u8], hard_cap: usize) -> Result<Inflate> {
    inflate(src, 0, hard_cap)
}

/// Deflate `data` with the zlib wrapper git uses (used by test fixtures).
pub fn deflate(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_after_two_streams() {
        let a = deflate(b"first object body");
        let b = deflate(b"second object body is longer");
        let mut combined = a.clone();
        combined.extend_from_slice(&b);
        let r1 = inflate(&combined, 0, 1 << 20).unwrap();
        assert!(r1.finished);
        assert_eq!(r1.data, b"first object body");
        // The next object starts exactly where the first stream ended.
        let r2 = inflate(&combined, r1.consumed, 1 << 20).unwrap();
        assert!(r2.finished);
        assert_eq!(r2.data, b"second object body is longer");
        assert_eq!(r1.consumed, a.len());
    }

    #[test]
    fn truncated_is_error() {
        let mut a = deflate(b"xxxxxxxxxxxxxxxxxxxxxx");
        a.truncate(a.len() - 3);
        assert!(inflate(&a, 0, 1 << 20).is_err());
    }

    #[test]
    fn hard_cap_guard() {
        let big = vec![b'z'; 10_000];
        let z = deflate(&big);
        let r = inflate(&z, 0, 100).unwrap();
        assert!(r.over_cap);
        assert_eq!(r.data.len(), 101);
    }
}
