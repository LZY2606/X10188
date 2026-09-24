//! Bounded zlib decompression with exact stream-boundary detection.

use flate2::{Decompress, FlushDecompress, Status};

#[derive(Debug)]
pub enum InflateError {
    /// Output tried to exceed the declared/allowed cap (size spoofing).
    CapExceeded { cap: usize, attempted: usize },
    /// Stream ended before a complete zlib frame was available.
    Truncated,
    Corrupt(String),
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InflateError::CapExceeded { cap, attempted } => write!(
                f,
                "declared size {} contradicted by stream (>= {} bytes produced)",
                cap, attempted
            ),
            InflateError::Truncated => write!(f, "truncated zlib stream"),
            InflateError::Corrupt(m) => write!(f, "zlib corrupt: {}", m),
        }
    }
}

impl std::error::Error for InflateError {}

/// Inflate exactly one zlib frame from `input`.
///
/// Returns `(data, consumed)` where `consumed` is the number of input bytes
/// belonging to the frame (the byte immediately after it is the pack CRC).
/// Decompression aborts as soon as more than `cap` output bytes appear, so a
/// lying size header is discovered mid-stream instead of after full expansion.
pub fn inflate_bounded(input: &[u8], cap: usize) -> Result<(Vec<u8>, usize), InflateError> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let consumed_before = d.total_in() as usize;
        if consumed_before >= input.len() {
            return Err(InflateError::Truncated);
        }
        let out_before = d.total_out() as usize;
        let status = d
            .inflate(&input[consumed_before..], &mut tmp, FlushDecompress::None)
            .map_err(|e| InflateError::Corrupt(e.to_string()))?;
        let produced = d.total_out() as usize - out_before;
        let consumed = d.total_in() as usize;
        if out.len() + produced > cap {
            return Err(InflateError::CapExceeded {
                cap,
                attempted: out.len() + produced,
            });
        }
        out.extend_from_slice(&tmp[..produced]);
        match status {
            Status::StreamEnd => return Ok((out, consumed)),
            Status::Ok | Status::BufError => {
                if consumed == consumed_before && produced == 0 {
                    return Err(InflateError::Truncated);
                }
            }
        }
    }
}
