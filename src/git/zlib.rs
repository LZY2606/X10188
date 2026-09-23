//! Bounded zlib decompression with explicit stream-boundary and checksum checks.
//!
//! Git stores compressed payloads as complete [RFC1950](https://www.rfc-editor.org/rfc/rfc1950)
//! zlib streams (2-byte header, deflate data, 4-byte adler32 trailer). We need three things
//! ordinary "decompress this whole buffer" helpers do not give us:
//!
//! 1. The exact number of compressed bytes consumed, so subsequent pack entries can be located.
//! 2. An explicit adler32 verification, surfaced separately from stream corruption.
//! 3. Overshoot ("size spoof") detection when the real output exceeds the declared size.

use flate2::{Decompress, FlushDecompress};

pub fn adler32(data: &[u8]) -> u32 {
    const MOD: u32 = 65521;
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % MOD;
        b = (b + a) % MOD;
    }
    (b << 16) | a
}

#[derive(Debug)]
pub struct Inflated {
    pub data: Vec<u8>,
    /// Total compressed bytes consumed, including the 2-byte header and 4-byte trailer.
    pub consumed: usize,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum InflateError {
    /// Expected declared size was exceeded. `produced` bytes (at least expected+1) were seen.
    SizeOvershoot { expected: u64, produced: u64 },
    /// Stream ended before the declared output size was reached.
    Truncated { expected: u64, produced: u64 },
    /// Deflate data could not be decoded.
    Corrupt(String),
    /// Stream decoded, but the adler32 trailer does not match the output.
    CrcMismatch,
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InflateError::SizeOvershoot { expected, produced } => write!(
                f,
                "decompressed size spoof: declared {expected}, actual >= {produced}"
            ),
            InflateError::Truncated { expected, produced } => {
                write!(f, "truncated zlib stream: declared {expected}, got {produced}")
            }
            InflateError::Corrupt(s) => write!(f, "corrupt zlib stream: {s}"),
            InflateError::CrcMismatch => f.write_str("adler32 checksum mismatch"),
        }
    }
}

impl std::error::Error for InflateError {}

/// Inflate a single zlib stream beginning at `input[start]`.
///
/// `expected_size` bounds the output: one extra byte of slack is used as a canary so that an
/// overshoot is discovered mid-stream instead of being silently truncated.
pub fn inflate_stream(input: &[u8], start: usize, expected_size: u64) -> Result<Inflated, InflateError> {
    let cap = expected_size.saturating_add(1).min(64 * 1024 * 1024) as usize;
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(expected_size as usize + 1));
    let mut dec = Decompress::new(false);
    let mut input_pos = start;
    let mut produced: u64 = 0;

    loop {
        if produced > expected_size {
            return Err(InflateError::SizeOvershoot {
                expected: expected_size,
                produced,
            });
        }
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let mut chunk_out = [0u8; 16 * 1024];
        let in_slice = &input[input_pos..];
        if in_slice.is_empty() {
            return Err(InflateError::Truncated {
                expected: expected_size,
                produced,
            });
        }
        let status = dec
            .decompress(in_slice, &mut chunk_out, FlushDecompress::None)
            .map_err(|e| InflateError::Corrupt(e.to_string()))?;
        let read = (dec.total_in() - before_in) as usize;
        let wrote = (dec.total_out() - before_out) as usize;
        input_pos += read;
        produced += wrote as u64;
        out.extend_from_slice(&chunk_out[..wrote]);

        if produced > expected_size {
            return Err(InflateError::SizeOvershoot {
                expected: expected_size,
                produced,
            });
        }
        if status == flate2::Status::StreamEnd {
            if produced != expected_size {
                return Err(InflateError::Truncated {
                    expected: expected_size,
                    produced,
                });
            }
            // total_in is relative to the slice passed on the first call; we fed `&input[start..]`
            // indirectly through moving windows, so track absolute position manually.
            let consumed = input_pos - start;
            // consumed now points immediately after the trailer; validate it.
            if consumed < 6 {
                return Err(InflateError::Corrupt("stream too short".into()));
            }
            let trailer = &input[input_pos - 4..input_pos];
            let stored = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
            if stored != adler32(&out) {
                return Err(InflateError::CrcMismatch);
            }
            let _ = before_out;
            return Ok(Inflated { data: out, consumed });
        }
        if read == 0 && wrote == 0 {
            return Err(InflateError::Corrupt("decompressor stalled".into()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn exact_boundary() {
        let payload = b"hello pack chain microscope";
        let mut buf = zlib(payload);
        buf.extend_from_slice(b"TAIL");
        let inf = inflate_stream(&buf, 0, payload.len() as u64).unwrap();
        assert_eq!(inf.data, payload);
        assert_eq!(&buf[inf.consumed..], b"TAIL");
    }

    #[test]
    fn overshoot_detected() {
        let payload = vec![b'x'; 100];
        let buf = zlib(&payload);
        let err = inflate_stream(&buf, 0, 50).unwrap_err();
        matches!(err, InflateError::SizeOvershoot { expected: 50, .. });
    }

    #[test]
    fn truncated_detected() {
        let payload = vec![b'y'; 10];
        let buf = zlib(&payload);
        assert!(matches!(
            inflate_stream(&buf, 0, 100).unwrap_err(),
            InflateError::Truncated { .. }
        ));
    }

    #[test]
    fn crc_tamper_detected() {
        let payload = b"checksum me please";
        let mut buf = zlib(payload);
        let n = buf.len();
        buf[n - 1] ^= 0xff;
        // Either the deflate layer rejects the tamper, or our adler check does.
        let err = inflate_stream(&buf, 0, payload.len() as u64).unwrap_err();
        assert!(
            matches!(err, InflateError::CrcMismatch | InflateError::Corrupt(_)),
            "{err:?}"
        );
    }

    #[test]
    fn adler_known_vector() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E60398);
    }
}
