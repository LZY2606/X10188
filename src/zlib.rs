use flate2::{Decompress, FlushDecompress, Status};

pub struct ZlibOutcome {
    pub data: Vec<u8>,
    /// Bytes of the input consumed by the zlib stream (stream boundary).
    pub consumed: u64,
    pub complete: bool,
    pub error: Option<String>,
}

/// Decompress one zlib stream starting at `input[0]`, reporting the exact
/// stream boundary so the caller knows where the next pack entry begins.
pub fn decompress_stream(input: &[u8]) -> ZlibOutcome {
    let mut decomp = Decompress::new(true);
    let mut out_buf = vec![0u8; 64 * 1024];
    let mut produced: Vec<u8> = Vec::new();
    loop {
        let in_before = decomp.total_in() as usize;
        let out_before = decomp.total_out() as usize;
        if in_before >= input.len() {
            return ZlibOutcome {
                data: produced,
                consumed: in_before as u64,
                complete: false,
                error: Some("zlib stream truncated before end-of-stream".into()),
            };
        }
        match decomp.decompress(&input[in_before..], &mut out_buf, FlushDecompress::None) {
            Ok(status) => {
                let out_now = decomp.total_out() as usize;
                produced.extend_from_slice(&out_buf[..out_now - out_before]);
                if status == Status::StreamEnd {
                    return ZlibOutcome {
                        data: produced,
                        consumed: decomp.total_in(),
                        complete: true,
                        error: None,
                    };
                }
                if decomp.total_in() as usize == in_before && out_now == out_before {
                    return ZlibOutcome {
                        data: produced,
                        consumed: decomp.total_in(),
                        complete: false,
                        error: Some("zlib decoder made no progress".into()),
                    };
                }
            }
            Err(e) => {
                return ZlibOutcome {
                    data: produced,
                    consumed: decomp.total_in(),
                    complete: false,
                    error: Some(format!("zlib error: {e}")),
                };
            }
        }
    }
}

/// Decompress a buffer that should contain exactly one zlib stream.
pub fn decompress_all(input: &[u8]) -> Result<Vec<u8>, String> {
    let out = decompress_stream(input);
    if !out.complete {
        return Err(out.error.unwrap_or_else(|| "incomplete zlib stream".into()));
    }
    Ok(out.data)
}
