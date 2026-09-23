//! Boundary-aware zlib inflation.
//!
//! Git packs store each object as one independent zlib stream laid out
//! back-to-back, so the parser needs both the inflated bytes *and* the
//! number of compressed bytes consumed in order to find the next entry.
//! A truncated stream is a hard error; output exceeding the safety cap
//! (size-spoof / zip-bomb protection) is reported with progress evidence.

use std::io::Read;

#[derive(Debug)]
pub struct Inflated {
    pub data: Vec<u8>,
    /// Compressed bytes consumed by the zlib stream.
    pub consumed: usize,
}

#[derive(Debug)]
pub struct InflateError {
    pub code: &'static str,
    pub message: String,
    /// Output bytes produced before the failure (forensic evidence).
    pub partial_len: usize,
}

struct CountingReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Read for CountingReader<'a> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.pos >= self.buf.len() {
            return Ok(0);
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Inflate one complete zlib stream.
///
/// `hard_cap` bounds memory: if the stream inflates beyond it,
/// [`crate::model::error_code::SIZE_OVERFLOW`] is returned mid-way.
pub fn inflate(encoded: &[u8], hard_cap: u64) -> Result<Inflated, InflateError> {
    let reader = CountingReader { buf: encoded, pos: 0 };
    let mut dec = flate2::read::ZlibDecoder::new(reader);
    let mut data = Vec::new();
    let mut chunk = [0u8; 8192];
    let result: std::io::Result<()> = loop {
        match dec.read(&mut chunk) {
            Ok(0) => break Ok(()),
            Ok(n) => {
                data.extend_from_slice(&chunk[..n]);
                if data.len() as u64 > hard_cap {
                    break Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "inflated stream exceeds hard cap",
                    ));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => break Err(e),
        }
    };
    let consumed = dec.into_inner().pos;
    match result {
        Ok(()) => Ok(Inflated { data, consumed }),
        Err(e) => Err(InflateError {
            code: if data.len() as u64 > hard_cap {
                crate::model::error_code::SIZE_OVERFLOW
            } else {
                crate::model::error_code::ZLIB_ERROR
            },
            message: e.to_string(),
            partial_len: data.len(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    fn deflate(data: &[u8]) -> Vec<u8> {
        let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn roundtrip_with_consumed() {
        let payload = b"hello zlib boundary".repeat(10);
        let mut stream = deflate(&payload);
        let trailer = b"JUNK";
        stream.extend_from_slice(trailer);
        let got = inflate(&stream, 1 << 20).unwrap();
        assert_eq!(got.data, payload);
        assert_eq!(got.consumed, stream.len() - trailer.len());
    }

    #[test]
    fn truncated_is_error() {
        let stream = deflate(b"x".repeat(500));
        let cut = stream.len() - 3;
        let err = inflate(&stream[..cut], 1 << 20).unwrap_err();
        assert_eq!(err.code, crate::model::error_code::ZLIB_ERROR);
    }

    #[test]
    fn overflow_cap() {
        let stream = deflate(&vec![0u8; 10_000]);
        let err = inflate(&stream, 100).unwrap_err();
        assert_eq!(err.code, crate::model::error_code::SIZE_OVERFLOW);
        assert!(err.partial_len > 100);
    }
}
