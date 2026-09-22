use std::io::Read;

#[derive(Debug, Clone)]
pub struct InflateResult {
    pub data: Vec<u8>,
    pub consumed: usize,
    pub expected_size: u64,
    pub stream_truncated: bool,
    pub size_spoof: bool,
}

/// Inflate a zlib stream starting at `start`, stopping as soon as the stream
/// ends so the exact raw byte range (`consumed`) is known.
///
/// `declared_size` is the size advertised by the pack entry header. Output is
/// capped one byte beyond it so a size lie is detected during decompression
/// instead of after blowing the memory budget.
pub fn inflate_at(buf: &[u8], start: usize, declared_size: u64) -> InflateResult {
    let cap = (declared_size.saturating_add(1)).min(1 << 28) as usize;
    let mut decoder = flate2::read::ZlibDecoder::new(&buf[start..]);
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(1 << 20));
    let mut chunk = [0u8; 16 * 1024];
    let mut stream_truncated = false;
    let mut size_spoof = false;
    loop {
        match decoder.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() as u64 + n as u64 > declared_size {
                    size_spoof = true;
                }
                out.extend_from_slice(&chunk[..n]);
                if out.len() as u64 > declared_size {
                    break;
                }
            }
            Err(_) => {
                stream_truncated = true;
                break;
            }
        }
    }
    // get_ref() yields the still-unconsumed tail of the input slice.
    let remaining = decoder.get_ref().len();
    let consumed = buf.len() - start - remaining;
    InflateResult {
        data: out,
        consumed,
        expected_size: declared_size,
        stream_truncated,
        size_spoof,
    }
}

/// Inflate a complete, self-contained zlib blob (e.g. a loose object).
pub fn inflate_complete(buf: &[u8]) -> std::result::Result<Vec<u8>, String> {
    let mut decoder = flate2::read::ZlibDecoder::new(buf);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| format!("zlib: {e}"))?;
    Ok(out)
}
