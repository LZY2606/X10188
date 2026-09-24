//! zlib stream handling with exact input-boundary accounting.
//!
//! Every packed object is a standalone zlib stream. Forensically we need to
//! know precisely how many compressed bytes belong to the stream (the CRC
//! in the `.idx` covers exactly that byte range), whether the stream ended
//! cleanly, and whether the inflated size matches the header declaration.

use flate2::{Decompress, FlushDecompress, Status};

#[derive(Debug, Clone)]
pub struct InflateOutcome {
    pub data: Vec<u8>,
    pub input_consumed: usize,
    pub stream_done: bool,
}

#[derive(Debug)]
pub struct InflateError {
    pub message: String,
    pub partial: Vec<u8>,
    pub input_consumed: usize,
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "zlib: {}", self.message)
    }
}
impl std::error::Error for InflateError {}

/// Inflate a zlib stream starting at `input[start]`.
///
/// `declared_size` is the size promised by the pack header: producing one
/// byte beyond it is reported as a size spoof. `max_bytes` is an absolute
/// safety cap against a declared size that is merely huge rather than
/// smaller than the payload.
pub fn inflate_from(
    input: &[u8],
    start: usize,
    declared_size: Option<u64>,
    max_bytes: u64,
) -> Result<InflateOutcome, InflateError> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = start;
    let mut done = false;
    let mut err_msg: Option<String> = None;

    loop {
        let cap = 16 * 1024usize;
        let old = out.len();
        out.resize(old + cap, 0);

        let in_total_before = dec.total_in();
        let res = dec.decompress(&input[in_pos..], &mut out[old..], FlushDecompress::None);
        in_pos += (dec.total_in() - in_total_before) as usize;
        let produced = dec.total_out() as usize - old;
        out.truncate(old + produced);

        match res {
            Ok(Status::StreamEnd) => done = true,
            Ok(Status::Ok) => {}
            Err(e) => {
                err_msg = Some(e.to_string());
                break;
            }
            Ok(Status::BufError) => {
                err_msg = Some("buf error".into());
                break;
            }
        }

        if let Some(n) = declared_size {
            if out.len() as u64 > n {
                return Err(InflateError {
                    message: format!(
                        "size spoof: inflated payload exceeds declared size of {} bytes",
                        n
                    ),
                    partial: out,
                    input_consumed: in_pos - start,
                });
            }
        }
        if out.len() as u64 > max_bytes {
            return Err(InflateError {
                message: format!("output exceeded safety cap of {} bytes", max_bytes),
                partial: out,
                input_consumed: in_pos - start,
            });
        }
        if done {
            break;
        }
        if in_pos >= input.len() {
            break;
        }
    }

    if let Some(msg) = err_msg {
        return Err(InflateError {
            message: msg,
            partial: out,
            input_consumed: in_pos - start,
        });
    }
    if !done {
        return Err(InflateError {
            message: "truncated zlib stream: end-of-pack reached before stream end".into(),
            partial: out,
            input_consumed: in_pos - start,
        });
    }
    if let Some(n) = declared_size {
        if out.len() as u64 != n {
            return Err(InflateError {
                message: format!(
                    "size spoof: declared {} bytes but stream produced {} bytes",
                    n,
                    out.len()
                ),
                partial: out,
                input_consumed: in_pos - start,
            });
        }
    }
    Ok(InflateOutcome {
        data: out,
        input_consumed: in_pos - start,
        stream_done: true,
    })
}
