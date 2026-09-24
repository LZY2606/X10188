//! Bounded zlib decompression that reports the exact compressed-stream boundary.

use flate2::{Decompress, FlushDecompress, Status};
use std::fmt;

#[derive(Debug)]
pub enum InflateError {
    Corrupt(String),
    Truncated,
    /// Decompressed output exceeded the caller-supplied byte limit.
    LimitExceeded { limit: u64, so_far: u64 },
}

impl fmt::Display for InflateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InflateError::Corrupt(m) => write!(f, "zlib 数据损坏: {m}"),
            InflateError::Truncated => write!(f, "zlib 流被截断"),
            InflateError::LimitExceeded { limit, so_far } => {
                write!(f, "解压输出超过限制 (limit={limit}, 已产出={so_far})")
            }
        }
    }
}

impl std::error::Error for InflateError {}

pub struct Inflated {
    pub data: Vec<u8>,
    /// Number of compressed input bytes consumed (zlib stream boundary).
    pub consumed: u64,
}

/// Decompress a zlib stream starting at `data[0]`, stopping at the stream end.
/// `limit` caps the decompressed size (zip-bomb / size-fraud guard).
pub fn inflate_bounded(data: &[u8], limit: u64) -> Result<Inflated, InflateError> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 16384];
    loop {
        let in_before = dec.total_in();
        let out_before = dec.total_out();
        let input = &data[in_before as usize..];
        let status = dec
            .decompress(input, &mut buf, FlushDecompress::None)
            .map_err(|e| InflateError::Corrupt(e.to_string()))?;
        let produced = (dec.total_out() - out_before) as usize;
        out.extend_from_slice(&buf[..produced]);
        if out.len() as u64 > limit {
            return Err(InflateError::LimitExceeded {
                limit,
                so_far: out.len() as u64,
            });
        }
        match status {
            Status::StreamEnd => {
                return Ok(Inflated {
                    data: out,
                    consumed: dec.total_in(),
                })
            }
            Status::Ok | Status::BufError => {
                let consumed_input = dec.total_in() > in_before;
                if !consumed_input && produced == 0 {
                    // No progress possible: input exhausted before stream end.
                    return Err(InflateError::Truncated);
                }
            }
        }
    }
}
