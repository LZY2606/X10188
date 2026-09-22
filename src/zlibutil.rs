use flate2::Decompress;

pub fn inflate_full(input: &[u8]) -> Result<Vec<u8>, String> {
    let mut d = Decompress::new(true);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut in_pos = 0;
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let in_avail = input.len() - in_pos;
        if in_avail == 0 {
            return Err("truncated zlib stream".into());
        }
        let res = d.decompress(
            &input[in_pos..],
            &mut buf,
            flate2::FlushDecompress::None,
        );
        in_pos += (d.total_in() - before_in) as usize;
        let produced = (d.total_out() - before_out) as usize;
        out.extend_from_slice(&buf[..produced]);
        match res {
            Ok(flate2::Status::Ok) => {}
            Ok(flate2::Status::StreamEnd) => break,
            Err(e) => return Err(e.to_string()),
            Ok(flate2::Status::BufError) => {
                if in_pos == input.len() {
                    return Err("truncated zlib stream".into());
                }
            }
        }
        let _ = in_avail;
    }
    Ok(out)
}

pub struct InflateResult {
    pub data: Vec<u8>,
    pub consumed_in: usize,
    pub ended: bool,
    pub over_limit: bool,
    pub error: Option<String>,
}

/// Inflate a zlib stream beginning at `input[start..]`.
/// Output is capped at `cap` bytes; if more than `cap` decompressed bytes exist
/// (declared-size spoof), `over_limit` is set and parsing stops.
pub fn inflate_entry(input: &[u8], start: usize, cap: u64) -> InflateResult {
    let mut d = Decompress::new(true);
    let mut data = Vec::new();
    let mut buf = [0u8; 16 * 1024];
    let mut in_pos = start;
    let mut ended = false;
    let mut error = None;
    let mut over_limit = false;
    loop {
        if in_pos >= input.len() {
            error = Some("zlib stream truncated before entry boundary".into());
            break;
        }
        let before_in = d.total_in();
        let before_out = d.total_out();
        let res = d.decompress(
            &input[in_pos..],
            &mut buf,
            flate2::FlushDecompress::None,
        );
        in_pos += (d.total_in() - before_in) as usize;
        let produced = (d.total_out() - before_out) as usize;
        if data.len() as u64 + produced as u64 > cap {
            let room = (cap as usize).saturating_sub(data.len());
            data.extend_from_slice(&buf[..room.min(produced)]);
            over_limit = true;
            break;
        }
        data.extend_from_slice(&buf[..produced]);
        match res {
            Ok(flate2::Status::Ok) => {}
            Ok(flate2::Status::StreamEnd) => {
                ended = true;
                break;
            }
            Ok(flate2::Status::BufError) => {}
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
    }
    InflateResult {
        data,
        consumed_in: in_pos,
        ended,
        over_limit,
        error,
    }
}
