use flate2::{Decompress, FlushDecompress, Status};

pub struct InflateResult {
    pub out: Vec<u8>,
    /// Bytes of input consumed up to and including the zlib end marker.
    pub consumed: usize,
    pub stream_end: bool,
}

/// Inflate a zlib stream starting at `data[start]`.
///
/// Decompression is performed in bounded chunks. If the stream emits more than
/// `cap` output bytes, an error is returned ("size spoof") - this lets us
/// detect a lying size header mid-inflation rather than trusting it up front.
/// The exact zlib boundary is recovered through `total_in`.
pub fn inflate_stream(data: &[u8], start: usize, cap: u64) -> Result<InflateResult, String> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = start;
    loop {
        if in_pos >= data.len() {
            return Err("zlib stream truncated before end".into());
        }
        let mut tmp = [0u8; 16 * 1024];
        let total_out_before = dec.total_out();
        let status = dec
            .decompress(&data[in_pos..], &mut tmp, FlushDecompress::None)
            .map_err(|e| format!("zlib error: {}", e))?;
        let produced = (dec.total_out() - total_out_before) as usize;
        out.extend_from_slice(&tmp[..produced]);
        in_pos = start + dec.total_in() as usize;
        if dec.total_out() > cap {
            return Err(format!(
                "inflated size spoof: stream produced {} bytes (cap {})",
                dec.total_out(),
                cap
            ));
        }
        match status {
            Status::StreamEnd => {
                return Ok(InflateResult {
                    out,
                    consumed: dec.total_in() as usize,
                    stream_end: true,
                });
            }
            Status::Ok => {
                if dec.needs_input() && in_pos >= data.len() {
                    return Err("zlib stream truncated before end".into());
                }
            }
            Status::BufError => {
                // Both buffers fully used; loop continues with remaining input.
            }
        }
    }
}

/// Deflate `data` as a zlib stream (used by the in-repo test pack builder;
/// core analysis never shells out to git).
pub fn deflate_zlib(data: &[u8]) -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}
