//! Bounded zlib (RFC1950) decompression used for every packed/loose object.
//!
//! The decompressor never trusts the length encoded in the pack entry header.
//! Allocation is capped by an explicit hard byte budget so a forged object that
//! declares a tiny size but expands into a zip bomb is caught mid-flight.

use flate2::Decompress;

#[derive(Debug)]
pub struct InflateOutcome {
    pub data: Vec<u8>,
    /// Number of compressed bytes consumed up to and including the stream end.
    pub consumed: usize,
    pub reached_end: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum InflateError {
    /// zlib returned a hard error (bad header / bad data / invalid tree ...).
    Corrupt(String),
    /// Input ended before the zlib stream terminated.
    Truncated,
    /// Inflated payload exceeded the hard memory cap.
    HardCapExceeded { cap: usize, produced: usize },
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InflateError::Corrupt(s) => write!(f, "zlib 损坏: {}", s),
            InflateError::Truncated => write!(f, "zlib 流提前结束（截断）"),
            InflateError::HardCapExceeded { cap, produced } => write!(
                f,
                "解压硬上限 {} 字节被突破（已产出 {} 字节，疑似大小欺骗）",
                cap, produced
            ),
        }
    }
}

/// Inflate a zlib-wrapped stream contained at the start of `input`.
///
/// `hard_cap` bounds both output allocation and total inflation work.
pub fn inflate_bounded(input: &[u8], hard_cap: usize) -> Result<InflateOutcome, InflateError> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let chunk = 16 * 1024;
    let mut tmp = vec![0u8; chunk];

    loop {
        let before_out = d.total_out();
        let in_pos = d.total_in() as usize;
        let avail_in = &input[in_pos..];
        let no_more_input = avail_in.is_empty();
        let status = d
            .decompress(avail_in, &mut tmp, flate2::FlushDecompress::None)
            .map_err(|e| InflateError::Corrupt(e.to_string()))?;
        let produced = (d.total_out() - before_out) as usize;
        let consumed_now = d.total_in() as usize - in_pos;
        if produced > tmp.len() {
            // decompress can never produce more than the output buffer
            return Err(InflateError::Corrupt("解压输出超出缓冲区".into()));
        }
        out.extend_from_slice(&tmp[..produced]);

        if out.len() > hard_cap {
            return Err(InflateError::HardCapExceeded {
                cap: hard_cap,
                produced: out.len(),
            });
        }

        match status {
            flate2::Status::StreamEnd => {
                return Ok(InflateOutcome {
                    data: out,
                    consumed: d.total_in() as usize,
                    reached_end: true,
                });
            }
            flate2::Status::Ok => {
                // No input remaining and no progress made: the stream ended
                // before producing its terminating marker.
                if no_more_input && consumed_now == 0 && produced == 0 {
                    return Err(InflateError::Truncated);
                }
                if d.total_in() as usize >= input.len() {
                    // All input consumed but stream is not finished yet.
                    continue;
                }
            }
            flate2::Status::BufError => {
                // Both buffers reported full with no progress; enlarge output.
                if produced == 0 && consumed_now == 0 {
                    tmp.resize(tmp.len() * 2, 0);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    fn z(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn roundtrip_with_trailing_bytes() {
        let plain = b"hello pack chain microscope".repeat(50);
        let mut comp = z(&plain);
        comp.extend_from_slice(b"GARBAGE");
        let r = inflate_bounded(&comp, 10_000_000).unwrap();
        assert_eq!(r.data, plain);
        assert!(r.reached_end);
        assert_eq!(&comp[r.consumed..], b"GARBAGE");
    }

    #[test]
    fn truncated_is_detected() {
        let comp = z(b"partial payload");
        let cut = comp.len() - 2;
        assert_eq!(
            inflate_bounded(&comp[..cut], 10_000).unwrap_err(),
            InflateError::Truncated
        );
    }

    #[test]
    fn hard_cap_trips() {
        let plain = vec![0x61u8; 100_000];
        let comp = z(&plain);
        let err = inflate_bounded(&comp, 1024).unwrap_err();
        assert!(matches!(err, InflateError::HardCapExceeded { .. }));
    }
}
