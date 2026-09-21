//! zlib (RFC1950) decompression with precise consumed-length tracking,
//! so a pack entry knows exactly where the next object begins.

use flate2::{Decompress, FlushDecompress, Status};

#[derive(Debug)]
pub struct Inflated {
    pub data: Vec<u8>,
    pub consumed: usize,
}

/// Decompress a single zlib member starting at `input[offset..]`.
/// `limit` bounds the output buffer expansion (size spoof protection).
pub fn inflate_member(input: &[u8], offset: usize, limit: usize) -> Result<Inflated, String> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut cap = 4096usize;
    loop {
        out.resize(cap, 0);
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let status = dec
            .decompress(
                &input[offset + before_in as usize..],
                &mut out[before_out as usize..],
                FlushDecompress::Finish,
            )
            .map_err(|e| format!("zlib error: {e}"))?;
        let produced = (dec.total_out() - before_out) as usize;
        out.truncate((before_out as usize) + produced);
        match status {
            Status::StreamEnd => {
                return Ok(Inflated {
                    data: out,
                    consumed: dec.total_in() as usize,
                });
            }
            Status::Ok => {
                if dec.total_in() as usize == input.len() - offset {
                    return Err("truncated zlib stream: input exhausted before stream end".into());
                }
                let need = dec.total_out() as usize + 1;
                if need > limit {
                    return Err(format!(
                        "inflated data exceeds safety limit of {limit} bytes"
                    ));
                }
                cap = (cap.saturating_mul(2)).max(need).min(limit + 1);
            }
            Status::BufError => {
                let need = dec.total_out() as usize + 4096;
                if need > limit {
                    return Err(format!(
                        "inflated data exceeds safety limit of {limit} bytes"
                    ));
                }
                cap = need;
            }
        }
    }
}

/// Deflate helper used by the test fixture kit to build zlib members.
pub fn deflate(data: &[u8]) -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}
