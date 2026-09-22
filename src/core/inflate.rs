// Boundary-aware zlib decompression. We never invoke the `git` binary.

use flate2::Decompress;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InflateError {
    /// Compressed stream itself is malformed / cannot be completed.
    ZlibError(String),
    /// Decompressed length does not match the header-advertised length.
    SizeMismatch { declared: u64, actual: u64 },
    /// Stream keeps emitting data beyond the declared size (size spoof attempt).
    SizeSpoof { declared: u64 },
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InflateError::ZlibError(s) => write!(f, "zlib error: {s}"),
            InflateError::SizeMismatch { declared, actual } => write!(
                f,
                "declared inflated size {declared} but stream produced {actual} bytes"
            ),
            InflateError::SizeSpoof { declared } => write!(
                f,
                "stream produced more than declared size {declared} (possible size spoof)"
            ),
        }
    }
}

pub struct InflateResult {
    pub data: Vec<u8>,
    /// Number of compressed bytes consumed (the exact zlib stream boundary).
    pub consumed: usize,
}

/// Inflate exactly one zlib stream taken from `src[start..]`.
///
/// `declared_size` is the size advertised by the enclosing container (pack
/// entry header or loose object header). The inflator allows at most
/// `declared_size + 1` bytes to emerge: if any byte appears after the declared
/// size, [`InflateError::SizeSpoof`] is returned so that a lie discovered only
/// halfway through decompression cannot be mistaken for a complete object.
pub fn inflate_stream(
    src: &[u8],
    start: usize,
    declared_size: u64,
) -> Result<InflateResult, InflateError> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut pos = start;
    let cap = declared_size.saturating_add(1) as usize;
    loop {
        let remaining_in = src.len().saturating_sub(pos);
        if remaining_in == 0 {
            return Err(InflateError::ZlibError(
                "compressed stream truncated before stream end".into(),
            ));
        }
        let avail_out = cap.saturating_sub(out.len()).max(1);
        let out_before = out.len();
        let in_before = d.total_in();
        out.resize(out_before + avail_out, 0);
        let before = d.total_out();
        let ret = d
            .inflate(
                &src[pos..],
                &mut out[out_before..],
                flate2::FlushDecompress::None,
            )
            .map_err(|e| InflateError::ZlibError(e.to_string()))?;
        let produced = (d.total_out() - before) as usize;
        out.truncate(out_before + produced);
        pos += (d.total_in() - in_before) as usize;

        if out.len() > declared_size as usize {
            return Err(InflateError::SizeSpoof {
                declared: declared_size,
            });
        }

        if ret == flate2::Status::StreamEnd {
            break;
        }
        if ret == flate2::Status::BufError && produced == 0 {
            // Should not normally happen since we always offer input/output;
            // treat as a malformed stream rather than spinning forever.
            return Err(InflateError::ZlibError("decompressor stalled".into()));
        }
    }
    if out.len() as u64 != declared_size {
        return Err(InflateError::SizeMismatch {
            declared: declared_size,
            actual: out.len() as u64,
        });
    }
    Ok(InflateResult {
        data: out,
        consumed: pos - start,
    })
}
