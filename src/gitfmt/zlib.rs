//! Streaming zlib decompression with precise stream-boundary reporting.
//! We need to know where the zlib stream ends (pack objects are concatenated)
//! and detect declared-vs-actual size lies ("half-way size spoof"). Even when a
//! size lie is discovered mid-stream we keep scanning to find the stream end,
//! so a bad object can be isolated without aborting the whole pack.

use miniz_oxide::inflate::core::{decompress, inflate_flags, DecompressorOxide};
use miniz_oxide::inflate::{TINFLStatus, TINFL_FLAG_PARSE_ZLIB_HEADER};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InflateError {
    /// Compressed stream itself is invalid/truncated; boundary is unusable.
    BadStream(String),
    /// Decompressed data exceeds the hard per-object safety cap.
    CapExceeded { cap: u64 },
}

#[derive(Debug, Clone)]
pub struct Inflated {
    pub data: Vec<u8>,
    /// Offset in the input just past the end of the zlib stream.
    pub compressed_end: usize,
    pub compressed_len: usize,
    /// `(declared, actual)` when the advertised size did not match.
    pub size_mismatch: Option<(u64, u64)>,
}

/// Inflate a zlib stream beginning at `start`.
///
/// * `expected_size` — size advertised by the pack entry / loose header.
/// * `hard_cap` — maximum output bytes we are willing to emit.
pub fn inflate_at(
    buf: &[u8],
    start: usize,
    expected_size: Option<u64>,
    hard_cap: u64,
) -> Result<Inflated, InflateError> {
    let mut d = DecompressorOxide::new();
    let flags = inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF
        | TINFL_FLAG_PARSE_ZLIB_HEADER;

    let mut output: Vec<u8> = Vec::new();
    let mut in_pos = start;
    let mut total_out = 0usize;
    // Once the actual output passes the declared size we stop trusting the
    // header but keep scanning (bounded by hard_cap) to find the stream end.
    let mut lie_bigger = false;

    loop {
        if total_out as u64 >= hard_cap {
            return Err(InflateError::CapExceeded { cap: hard_cap });
        }
        if let Some(declared) = expected_size
            && !lie_bigger
            && total_out as u64 > declared
        {
            lie_bigger = true;
        }

        let bound = if lie_bigger || expected_size.is_none() {
            hard_cap as usize
        } else {
            expected_size.unwrap() as usize
        };
        let target = (total_out + (1 << 20)).min(bound).max(total_out + 1);
        output.resize(target, 0);

        let input = if in_pos < buf.len() {
            &buf[in_pos..]
        } else {
            &[][..]
        };
        let (status, read, written) =
            decompress(&mut d, input, &mut output[..], total_out, flags);
        in_pos += read;
        total_out += written;

        if total_out as u64 > hard_cap {
            return Err(InflateError::CapExceeded { cap: hard_cap });
        }
        if let Some(declared) = expected_size
            && !lie_bigger
            && total_out as u64 > declared
        {
            lie_bigger = true;
        }

        match status {
            TINFLStatus::Done => {
                output.truncate(total_out);
                break;
            }
            TINFLStatus::HasMoreOutput => continue,
            TINFLStatus::NeedsMoreInput => {
                if in_pos >= buf.len() {
                    return Err(InflateError::BadStream(
                        "zlib stream truncated: needs more input".into(),
                    ));
                }
            }
            other => {
                return Err(InflateError::BadStream(format!(
                    "zlib decompression failed: {other:?}"
                )));
            }
        }
    }

    let size_mismatch = match expected_size {
        Some(declared) if declared != total_out as u64 => {
            Some((declared, total_out as u64))
        }
        _ => None,
    };

    Ok(Inflated {
        data: output,
        compressed_end: in_pos,
        compressed_len: in_pos - start,
        size_mismatch,
    })
}

/// Deflate helper used by the test fixtures (RFC1950 zlib stream).
pub fn deflate(data: &[u8]) -> Vec<u8> {
    use miniz_oxide::deflate::compress_to_vec_zlib;
    compress_to_vec_zlib(data, 6)
}
