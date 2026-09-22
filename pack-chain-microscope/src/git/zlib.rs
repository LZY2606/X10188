use flate2::{Decompress, FlushDecompress};

use super::checksum::adler32;

#[derive(Debug)]
pub struct ZlibStream {
    pub data: Vec<u8>,
    /// Number of input bytes consumed from `start`, including the 4-byte adler trailer.
    pub consumed: usize,
    pub adler_expected: u32,
    pub adler_actual: u32,
    pub adler_ok: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ZlibError {
    /// Truncated or malformed deflate data; the scan cannot continue past it.
    Truncated(String),
    BadZlibHeader,
}

/// Inflate a zlib stream beginning at `input[start]`.
///
/// The deflate body is validated by `flate2`; the trailing adler32 is checked
/// separately so a corrupt CRC can be isolated without losing the payload.
pub fn inflate_at(input: &[u8], start: usize) -> Result<ZlibStream, ZlibError> {
    if start + 2 > input.len() {
        return Err(ZlibError::Truncated("zlib header missing".into()));
    }
    let cmf = input[start];
    let flg = input[start + 1];
    if cmf & 0x0f != 8 || ((cmf as u16) << 8 | flg as u16) as u16 % 31 != 0 {
        return Err(ZlibError::BadZlibHeader);
    }
    let dict = flg & 0x20 != 0;
    let body_start = if dict {
        if start + 6 > input.len() {
            return Err(ZlibError::Truncated("fdict dictid missing".into()));
        }
        start + 6
    } else {
        start + 2
    };

    let mut dec = Decompress::new(false);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let mut buf = [0u8; 16384];
        let res = dec.decompress(&input[(body_start + before_in as usize)..], &mut buf, FlushDecompress::Finish);
        out.extend_from_slice(&buf[..(dec.total_out() - before_out) as usize]);
        match res {
            Ok(flate2::Status::Ok) | Ok(flate2::Status::BufError) => {
                if dec.total_in() == before_in && dec.total_out() == before_out {
                    // No progress: input exhausted before StreamEnd.
                    return Err(ZlibError::Truncated("deflate stream ended early".into()));
                }
                continue;
            }
            Ok(flate2::Status::StreamEnd) => break,
            Err(e) => return Err(ZlibError::Truncated(e.to_string())),
        }
    }
    let trailer_at = body_start + dec.total_in() as usize;
    if trailer_at + 4 > input.len() {
        return Err(ZlibError::Truncated("adler trailer missing".into()));
    }
    let expected = u32::from_be_bytes([
        input[trailer_at],
        input[trailer_at + 1],
        input[trailer_at + 2],
        input[trailer_at + 3],
    ]);
    let actual = adler32(&out);
    Ok(ZlibStream {
        data: out,
        consumed: (trailer_at + 4) - start,
        adler_expected: expected,
        adler_actual: actual,
        adler_ok: expected == actual,
    })
}
