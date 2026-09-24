//! Bounded raw zlib decompression with explicit stream-boundary tracking.
//!
//! A forensic parser cannot trust the size a pack entry declares in its
//! header. We inflate with a hard ceiling and separately report how many
//! bytes the stream produced so callers can detect "大小欺骗":
//! declared size != inflated size.

use flate2::{Decompress, FlushDecompress};

/// Outcome of inflating one zlib member.
#[derive(Clone, Debug)]
pub struct Inflated {
    pub data: Vec<u8>,
    /// Bytes of compressed input consumed, i.e. the end offset of the zlib
    /// stream within the source file.
    pub consumed: usize,
}

/// Inflates a single zlib member beginning at `input[0]`.
///
/// * `max_output` — hard ceiling on produced bytes (resource budget).
/// * The stream must terminate cleanly at its own end marker; bytes after the
///   member are ignored and the member's length appears in `consumed`.
pub fn inflate_once(input: &[u8], max_output: usize) -> Result<Inflated, String> {
    let mut dec = Decompress::new(true);
    let mut out = Vec::new();
    let mut scratch = [0u8; 16 * 1024];
    loop {
        let remaining = &input[dec.total_in() as usize..];
        let before = dec.total_out();
        let res = dec.decompress(remaining, &mut scratch, FlushDecompress::Finish);
        let wrote = (dec.total_out() - before) as usize;
        out.extend_from_slice(&scratch[..wrote]);
        if out.len() > max_output {
            return Err(format!("inflated stream exceeds ceiling of {max_output} bytes"));
        }
        match res {
            Ok(flate2::Status::StreamEnd) => {
                return Ok(Inflated {
                    data: out,
                    consumed: dec.total_in() as usize,
                });
            }
            Ok(flate2::Status::Ok) => {
                // All input consumed without an explicit end marker => the
                // member is truncated (or we must supply more data).
                if dec.total_in() as usize >= input.len() {
                    return Err("zlib stream ended without end-of-stream marker".into());
                }
            }
            // Output slice full; enlarge and continue.
            Ok(flate2::Status::BufError) => {
                if wrote == 0 {
                    return Err("decompressor stalled".into());
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}
