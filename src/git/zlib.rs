use miniz_oxide::inflate::core::{inflate, DecompressorOxide, TINFLStatus};
use miniz_oxide::DataFormat;

#[derive(Debug, Clone)]
pub struct Inflated {
    pub data: Vec<u8>,
    pub input_consumed: usize,
    pub status_desc: String,
}

#[derive(Debug, Clone)]
pub enum InflateError {
    Failed(String),
}

/// Streaming zlib decompression with a hard cap on actually-produced bytes.
pub fn inflate_zlib(input: &[u8], max_out: usize) -> Result<Inflated, InflateError> {
    let mut decomp = Box::new(DecompressorOxide::new());
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = 0usize;
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let (status, in_consumed, out_consumed) =
            inflate(&mut decomp, &input[in_pos..], &mut chunk, 0, DataFormat::Zlib);
        out.extend_from_slice(&chunk[..out_consumed]);
        in_pos += in_consumed;
        if out.len() > max_out {
            return Err(InflateError::Failed(format!(
                "expanded output {} exceeds limit {}",
                out.len(),
                max_out
            )));
        }
        use TINFLStatus::*;
        match status {
            Done => {
                return Ok(Inflated {
                    data: out,
                    input_consumed: in_pos,
                    status_desc: "Done".into(),
                });
            }
            NeedsMoreInput | HasMoreOutput => {
                if in_consumed == 0 && out_consumed == 0 {
                    return Err(InflateError::Failed("inflate stalled".into()));
                }
            }
            Failed | HeaderMismatch => {
                return Err(InflateError::Failed(format!("inflate failed: {:?}", status)));
            }
        }
    }
}

pub fn deflate_zlib(data: &[u8]) -> Vec<u8> {
    let level = miniz_oxide::deflate::CompressionLevel::DefaultLevel as u8;
    miniz_oxide::deflate::compress_to_vec_zlib(data, level)
}

/// CRC32 (IEEE polynomial) used by v2 pack index CRC tables.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c: u32 = 0xffff_ffff;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            let mask = (c & 1).wrapping_neg();
            c = (c >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !c
}
