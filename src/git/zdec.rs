use flate2::Decompress;
use flate2::{FlushDecompress, Status};

#[derive(Clone, Debug)]
pub struct ZlibRange {
    pub compressed_start: usize,
    pub compressed_end: usize,
    pub output_len: usize,
}

/// Inflate one raw zlib stream beginning at `start`.
///
/// Returns the inflated bytes plus exact compressed-byte boundaries, so the
/// parser can continue at `compressed_end` without relying on the declared
/// size. Inflation is bounded by `max_output`; reaching that bound before the
/// stream ends is reported as a size/spoof error.
pub fn inflate_one(
    data: &[u8],
    start: usize,
    declared: u64,
    max_output: usize,
) -> Result<(Vec<u8>, ZlibRange), String> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut pos = start;
    let mut last_in = 0usize;
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        if pos >= data.len() {
            return Err("unexpected EOF inside zlib stream".into());
        }
        let before = dec.total_in();
        let before_out = dec.total_out();
        let res = dec.decompress(&data[pos..], &mut chunk, FlushDecompress::None)
            .map_err(|e| e.to_string())?;
        let consumed = (dec.total_in() - before) as usize;
        let produced = (dec.total_out() - before_out) as usize;
        pos += consumed;
        out.extend_from_slice(&chunk[..produced]);
        let _ = last_in;
        last_in = pos;
        if out.len() > max_output {
            return Err(format!(
                "inflated size {} exceeds hard cap {} (possible size spoof)",
                out.len(),
                max_output
            ));
        }
        if res == Status::StreamEnd {
            break;
        }
        if consumed == 0 && produced == 0 {
            return Err("zlib stream made no progress (corrupt data)".into());
        }
    }
    let out_len = out.len();
    if out_len as u64 != declared {
        return Err(format!(
            "size spoof: header declared {declared} bytes but zlib produced {out_len}"
        ));
    }
    Ok((
        out,
        ZlibRange {
            compressed_start: start,
            compressed_end: pos,
            output_len: out_len,
        },
    ))
}

/// Inflate without trusting any declared size (loose objects): only the hard
/// cap bounds the output.
pub fn inflate_unbounded(data: &[u8], start: usize, max_output: usize)
    -> Result<(Vec<u8>, ZlibRange), String>
{
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut pos = start;
    let mut chunk = vec![0u8; 16 * 1024];
    loop {
        if pos >= data.len() {
            return Err("unexpected EOF inside zlib stream".into());
        }
        let before = dec.total_in();
        let before_out = dec.total_out();
        let res = dec.decompress(&data[pos..], &mut chunk, FlushDecompress::None)
            .map_err(|e| e.to_string())?;
        let consumed = (dec.total_in() - before) as usize;
        let produced = (dec.total_out() - before_out) as usize;
        pos += consumed;
        out.extend_from_slice(&chunk[..produced]);
        if out.len() > max_output {
            return Err(format!(
                "inflated size {} exceeds hard cap {} (zip bomb suspected)",
                out.len(),
                max_output
            ));
        }
        if res == Status::StreamEnd {
            break;
        }
        if consumed == 0 && produced == 0 {
            return Err("zlib stream made no progress (corrupt data)".into());
        }
    }
    let out_len = out.len();
    Ok((
        out,
        ZlibRange {
            compressed_start: start,
            compressed_end: pos,
            output_len: out_len,
        },
    ))
}
