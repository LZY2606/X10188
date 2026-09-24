//! Bounded zlib decompression with exact compressed-boundary detection.
//!
//! Git packs concatenate per-object zlib streams back-to-back, so we must know
//! where each stream ends. `FlateDecomp` reports both consumed input bytes and
//! whether the declared inflated size is a lie.

use flate2::Decompress;
use flate2::FlushDecompress;

#[derive(Debug)]
pub struct ZlibOutcome {
    pub data: Vec<u8>,
    /// Number of input bytes the zlib stream occupied.
    pub consumed: usize,
    /// True if the zlib stream itself was valid and terminated cleanly.
    pub clean_end: bool,
    /// True when the real inflated length differs from `declared_size`.
    pub size_mismatch: bool,
}

#[derive(Debug)]
pub struct ZlibError {
    pub code: &'static str,
    pub message: String,
    pub consumed: usize,
}

/// Decompress one zlib stream beginning at `input[0]`.
///
/// `declared_size` is the size advertised by the pack entry header; it is never
/// trusted to bound output — the actual stream is always fully drained and the
/// two lengths are compared afterwards.
///
/// `hard_cap` bounds memory so a corrupt stream cannot expand without limit.
pub fn inflate_one(
    input: &[u8],
    declared_size: u64,
    hard_cap: usize,
) -> Result<ZlibOutcome, ZlibError> {
    let mut decomp = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let chunk = 16 * 1024;
    let mut clean_end = false;

    loop {
        let in_before = decomp.total_in();
        let out_before = decomp.total_out();
        let prev_len = out.len();
        out.resize(prev_len + chunk, 0u8);
        let inp_before = &input[decomp.total_in() as usize..];
        let result = decomp.decompress(
            inp_before,
            &mut out[prev_len..],
            FlushDecompress::None,
        );
        let used_in = (decomp.total_in() - in_before) as usize;
        let produced = (decomp.total_out() - out_before) as usize;
        out.truncate(prev_len + produced);

        match result {
            Ok(status) => {
                if status == flate2::Status::StreamEnd {
                    clean_end = true;
                    break;
                }
                if used_in == 0 && produced == 0 {
                    // No progress and not finished: truncated stream.
                    return Err(ZlibError {
                        code: "zlib_truncated",
                        message: "stream ended before zlib footer".into(),
                        consumed: decomp.total_in() as usize,
                    });
                }
            }
            Err(err) => {
                return Err(ZlibError {
                    code: "zlib_corrupt",
                    message: format!("zlib error: {}", err),
                    consumed: decomp.total_in() as usize,
                });
            }
        }

        if out.len() > hard_cap {
            return Err(ZlibError {
                code: "inflation_cap",
                message: format!("inflated stream exceeded hard cap of {} bytes", hard_cap),
                consumed: decomp.total_in() as usize,
            });
        }
    }

    let size_mismatch = out.len() as u64 != declared_size;
    Ok(ZlibOutcome {
        data: out,
        consumed: decomp.total_in() as usize,
        clean_end,
        size_mismatch,
    })
}

/// Convenience for loose objects (no declared size to compare).
pub fn inflate_loose(input: &[u8], hard_cap: usize) -> Result<(Vec<u8>, usize), ZlibError> {
    let o = inflate_one(input, 0, hard_cap)?;
    Ok((o.data, o.consumed))
}
