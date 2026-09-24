//! Bounded zlib decompression that also reports the exact compressed-stream
//! boundary (number of consumed input bytes), which a pack parser needs in
//! order to locate the next object entry.

use flate2::{Decompress, FlushDecompress, Status};

/// Hard safety cap so a forged size header cannot make us allocate unbounded
/// memory in one shot. Buffers grow incrementally up to this limit.
pub const HARD_CAP: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum ZlibError {
    /// The stream is corrupt.
    Corrupt(String),
    /// Input ended before the stream did.
    Truncated,
    /// Decompressed more than `max_out` bytes (possible size fraud).
    Overflow { produced: usize, max_out: usize },
}

impl std::fmt::Display for ZlibError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZlibError::Corrupt(e) => write!(f, "corrupt zlib stream: {e}"),
            ZlibError::Truncated => write!(f, "truncated zlib stream"),
            ZlibError::Overflow { produced, max_out } => {
                write!(f, "decompressed {produced} bytes exceeds limit {max_out}")
            }
        }
    }
}

/// Decompress a zlib stream starting at `input[0]`.
/// Returns (decompressed bytes, compressed bytes consumed).
pub fn decompress_bounded(input: &[u8], max_out: usize) -> Result<(Vec<u8>, usize), ZlibError> {
    let max_out = max_out.min(HARD_CAP);
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let chunk = 64 * 1024;
    loop {
        let consumed = d.total_in() as usize;
        let produced = d.total_out() as usize;
        if produced > max_out {
            return Err(ZlibError::Overflow { produced, max_out });
        }
        let offset = out.len();
        out.resize(offset + chunk, 0);
        let status = d
            .decompress(&input[consumed..], &mut out[offset..], FlushDecompress::None)
            .map_err(|e| ZlibError::Corrupt(e.to_string()))?;
        let new_produced = d.total_out() as usize;
        let new_consumed = d.total_in() as usize;
        out.truncate(new_produced);
        match status {
            Status::StreamEnd => return Ok((out, new_consumed)),
            Status::Ok | Status::BufError => {
                if new_consumed >= input.len() && new_produced == produced {
                    // No more input and no forward progress.
                    return Err(ZlibError::Truncated);
                }
                if new_produced > max_out {
                    return Err(ZlibError::Overflow {
                        produced: new_produced,
                        max_out,
                    });
                }
            }
        }
    }
}
