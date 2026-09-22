use flate2::{Decompress, FlushDecompress, Status};

use crate::error::{Error, Result};

pub fn inflate_limited(
    input: &[u8],
    expected_size: u64,
    hard_limit: u64,
) -> Result<(Vec<u8>, usize, Option<String>)> {
    let mut decompressor = Decompress::new(true);
    let mut output = Vec::new();
    let mut input_pos = 0;

    loop {
        if output.len() as u64 > hard_limit {
            return Err(Error::Corrupt(format!(
                "inflated data exceeds safety limit {hard_limit}"
            )));
        }
        let before_in = decompressor.total_in();
        let status = decompressor
            .decompress_vec(
                &input[input_pos..],
                &mut output,
                &mut [0u8; 0],
                FlushDecompress::None,
            )
            .map_err(|e| Error::Corrupt(format!("zlib stream error: {e}")))?;
        input_pos += (decompressor.total_in() - before_in) as usize;
        match status {
            Status::Ok => {
                if input_pos >= input.len() {
                    return Err(Error::Corrupt("truncated zlib stream".to_string()));
                }
            }
            Status::StreamEnd => {
                let warning = if output.len() as u64 == expected_size {
                    None
                } else {
                    Some(format!(
                        "declared size {expected_size}, inflated size {}",
                        output.len()
                    ))
                };
                return Ok((output, decompressor.total_in() as usize, warning));
            }
            Status::BufError => return Err(Error::Corrupt("zlib buffer error".into())),
        }
    }
}
