//! Bounded zlib inflation used for pack entries / loose objects.
//!
//! We inflate with a hard cap equal to the *declared* object size and track the
//! exact compressed byte boundary (needed to locate the next pack entry). If
//! the stream actually produces more bytes than advertised the result is a
//! `SizeSpoof` condition instead of unbounded allocation.

use std::io;

#[derive(Debug, Clone)]
pub struct InflateResult {
    pub data: Vec<u8>,
    /// Number of compressed bytes consumed from the input slice.
    pub consumed: usize,
    /// True if the zlib stream reached `StreamEnd`.
    pub stream_end: bool,
    /// True when inflation stopped because output exceeded `max_size`.
    pub limit_hit: bool,
}

/// Inflate `input` as a single zlib stream, stopping hard after `max_size`.
pub fn inflate_bounded(input: &[u8], max_size: usize) -> io::Result<InflateResult> {
    use flate2::{Decompress, FlushDecompress};

    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 8192];
    let mut stream_end = false;

    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let res = dec.decompress(input, &mut scratch, FlushDecompress::None)?;
        let produced = (dec.total_out() - before_out) as usize;
        out.extend_from_slice(&scratch[..produced]);

        if res == flate2::Status::StreamEnd {
            stream_end = true;
            break;
        }
        let consumed = (dec.total_in() - before_in) as usize;
        if produced == 0 && consumed == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "zlib stream made no progress (truncated?)",
            ));
        }
        if out.len() > max_size {
            return Ok(InflateResult {
                data: out,
                consumed: dec.total_in() as usize,
                stream_end: false,
                limit_hit: true,
            });
        }
    }

    Ok(InflateResult {
        consumed: dec.total_in() as usize,
        data: out,
        stream_end,
        limit_hit: false,
    })
}

/// Encode data as a zlib stream (used by the test fixture builder).
pub fn deflate(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}
