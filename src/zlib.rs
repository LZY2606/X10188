//! zlib (RFC 1950) decompression with exact stream-boundary tracking.
//!
//! A pack object's zlib stream is immediately followed by the *next* object,
//! so the parser must know exactly how many compressed bytes were consumed.
//! flate2's raw `Decompress` reports this precisely, which also lets us detect
//! truncated streams, over-long streams ("size spoof") and runaway expansion.

use flate2::{Decompress, FlushDecompress, Status};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inflated {
    pub data: Vec<u8>,
    pub consumed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZlibError {
    /// zlib returned an error mid stream.
    Corrupt(String),
    /// Available bytes ended before the zlib stream terminated.
    Truncated,
    /// Decompressed length exceeded the hard safety cap.
    TooBig,
    /// The header declared a size that disagrees with what was inflated.
    SizeMismatch { declared: usize, actual: usize },
}

impl std::fmt::Display for ZlibError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZlibError::Corrupt(s) => write!(f, "zlib corrupt: {s}"),
            ZlibError::Truncated => write!(f, "zlib stream truncated"),
            ZlibError::TooBig => write!(f, "decompressed data exceeds cap"),
            ZlibError::SizeMismatch { declared, actual } => write!(
                f,
                "size spoof: header declared {declared} bytes but stream produced {actual}"
            ),
        }
    }
}

impl std::error::Error for ZlibError {}

/// Decompress a zlib stream stored at the front of `input`.
///
/// `declared_size` comes from the pack entry header (or a delta size varint).
/// When `enforce_exact` is set, a mismatch with the produced length becomes
/// [`ZlibError::SizeMismatch`] — this is the "size spoof discovered halfway
/// through decompression" guard.  `hard_cap` bounds memory regardless of what
/// the header claims.
pub fn inflate_stream(
    input: &[u8],
    declared_size: Option<usize>,
    enforce_exact: bool,
    hard_cap: usize,
) -> Result<Inflated, ZlibError> {
    let mut d = Decompress::new(true);
    let hint = declared_size.unwrap_or(0).min(hard_cap).min(1 << 20);
    let mut out: Vec<u8> = Vec::with_capacity(hint);

    const CHUNK: usize = 16 * 1024;
    let mut consumed = 0usize;

    loop {
        let before = out.len();
        let grow = CHUNK.min(hard_cap.saturating_sub(before) + 1);
        if grow == 0 {
            return Err(ZlibError::TooBig);
        }
        out.resize(before + grow, 0);

        let in_before = d.total_in() as usize;
        let res = d.decompress(&input[consumed..], &mut out[before..], FlushDecompress::None);
        let produced = d.total_out() as usize - before;
        out.truncate(before + produced);
        consumed += (d.total_in() as usize) - in_before;

        match res {
            Ok(Status::StreamEnd) => break,
            Ok(Status::Ok) => {}
            Ok(Status::BufError) => {}
            Err(e) => return Err(ZlibError::Corrupt(e.to_string())),
        }

        if consumed >= input.len() {
            // Every byte handed to zlib was eaten but the stream never ended.
            return Err(ZlibError::Truncated);
        }
        if out.len() > hard_cap {
            return Err(ZlibError::TooBig);
        }
    }

    if let Some(declared) = declared_size
        && enforce_exact
        && out.len() != declared
    {
        return Err(ZlibError::SizeMismatch {
            declared,
            actual: out.len(),
        });
    }

    Ok(Inflated {
        data: out,
        consumed,
    })
}
