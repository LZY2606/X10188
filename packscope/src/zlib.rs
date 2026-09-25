use flate2::Decompress;
use std::io;

/// Result of inflating a zlib stream embedded in a larger byte buffer.
pub struct InflateResult {
    pub data: Vec<u8>,
    /// Absolute exclusive end of the zlib stream in the input buffer.
    pub consumed: usize,
}

/// Inflate one complete zlib stream beginning at `input[start..]`.
///
/// `max_output` bounds memory using the size declared in the pack header.
/// `slack` extra bytes are tolerated so a "size spoof" (declared size smaller
/// than the true inflated payload) is detected as an error instead of being
/// silently truncated.
pub fn inflate_at(
    input: &[u8],
    start: usize,
    max_output: usize,
    slack: usize,
) -> io::Result<InflateResult> {
    let cap = max_output.saturating_add(slack);
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut pos = start;
    loop {
        if pos >= input.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "zlib stream truncated before end marker",
            ));
        }
        let mut buf = [0u8; 16 * 1024];
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let res = dec.decompress(&input[pos..], &mut buf, flate2::FlushDecompress::None);
        pos += (dec.total_in() - before_in) as usize;
        let wrote = (dec.total_out() - before_out) as usize;
        out.extend_from_slice(&buf[..wrote]);
        match res {
            Ok(flate2::Status::StreamEnd) => {
                return Ok(InflateResult {
                    data: out,
                    consumed: start + dec.total_in() as usize,
                });
            }
            Ok(flate2::Status::Ok) => {
                if out.len() > cap {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "inflated {} bytes but header declared {} (slack {})",
                            out.len(),
                            max_output,
                            slack
                        ),
                    ));
                }
            }
            Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
        }
    }
}

/// Inflate a standalone zlib blob; reject trailing bytes.
pub fn inflate_exact(input: &[u8], max_output: usize, slack: usize) -> io::Result<Vec<u8>> {
    let r = inflate_at(input, 0, max_output, slack)?;
    if r.consumed != input.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} trailing byte(s) after zlib stream", input.len() - r.consumed),
        ));
    }
    Ok(r.data)
}

/// zlib-compress (used by test fixtures).
pub fn deflate(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use std::io::Write;
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}
