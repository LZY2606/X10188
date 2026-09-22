//! Zlib inflate with exact consumed-input tracking (zlib boundary detection).
//!
//! Uses `miniz_oxide` directly so no system zlib/git is required.

use miniz_oxide::inflate::core::{
    decompress as tinfl, inflate_flags, DecompressorOxide, TINFLStatus,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ZlibError {
    /// Invalid 2-byte zlib header.
    BadHeader,
    /// Stream is truncated / needs more input to finish.
    Truncated,
    /// Deflate data itself is corrupt (also covers adler32 mismatch).
    Corrupt(&'static str),
    /// Output exceeded the caller-provided cap (possible size-spoof bomb).
    OutputLimit,
}

#[derive(Debug, Clone)]
pub struct Inflated {
    pub data: Vec<u8>,
    /// Bytes consumed from the input up to and including the stream end.
    pub consumed: usize,
}

/// Validate a raw zlib (RFC1950) header.
pub fn check_zlib_header(input: &[u8]) -> Result<(), ZlibError> {
    if input.len() < 2 {
        return Err(ZlibError::Truncated);
    }
    let cmf = input[0];
    let flg = input[1];
    if cmf & 0x0f != 8 || ((cmf as u16) * 256 + flg as u16) % 31 != 0 || flg & 0x20 != 0 {
        return Err(ZlibError::BadHeader);
    }
    Ok(())
}

/// Inflate one complete zlib stream located at the start of `input`.
///
/// `max_output` hard-limits decompressed size. On success [`Inflated::consumed`]
/// is the exact number of bytes of `input` the stream occupied, so consecutive
/// objects inside a pack can be located by offsets alone.
pub fn inflate_one(input: &[u8], max_output: usize) -> Result<Inflated, ZlibError> {
    check_zlib_header(input)?;

    let mut d = DecompressorOxide::new();
    let mut out: Vec<u8> = Vec::new();
    let mut consumed: usize = 0;
    let mut cap = 4096usize.min(max_output).max(if max_output == 0 { 0 } else { 64 });
    loop {
        let start_len = out.len();
        out.resize(cap, 0);
        let flags = inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        let (status, in_n, out_n) = tinfl(&mut d, &input[consumed..], &mut out, start_len, flags);
        consumed += in_n;
        out.truncate(start_len + out_n);
        match status {
            TINFLStatus::Done => {
                return Ok(Inflated {
                    data: out,
                    consumed,
                })
            }
            TINFLStatus::HasMoreOutput => {
                if out.len() >= max_output {
                    return Err(ZlibError::OutputLimit);
                }
                cap = (cap.saturating_mul(2)).min(max_output).max(out.len() + 1);
            }
            TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
                return Err(ZlibError::Truncated)
            }
            TINFLStatus::Adler32Mismatch => return Err(ZlibError::Corrupt("adler32")),
            TINFLStatus::BadParam => return Err(ZlibError::Corrupt("bad-param")),
            TINFLStatus::Failed => return Err(ZlibError::Corrupt("failed")),
        }
    }
}
