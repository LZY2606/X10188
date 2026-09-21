use flate2::{Decompress, FlushDecompress, Status};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ZlibError {
    #[error("zlib 数据损坏: {0}")]
    Corrupt(String),
    #[error("zlib 流被截断")]
    Truncated,
    #[error("解压输出超过上限 {0} 字节")]
    TooBig(u64),
}

/// 解压一段 zlib 流,返回 (输出, 消耗的输入字节数)。
/// 消耗的输入字节数即压缩流的精确边界,用于定位 pack 中下一个对象。
pub fn decompress_bounded(input: &[u8], max_out: u64) -> Result<(Vec<u8>, usize), ZlibError> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let consumed = d.total_in() as usize;
        if consumed >= input.len() {
            return Err(ZlibError::Truncated);
        }
        let in_before = d.total_in();
        let out_before = d.total_out();
        match d.decompress_vec(&input[consumed..], &mut out, FlushDecompress::None) {
            Ok(Status::StreamEnd) => return Ok((out, d.total_in() as usize)),
            Ok(_) => {
                if d.total_in() == in_before && d.total_out() == out_before {
                    return Err(ZlibError::Truncated);
                }
                if out.len() as u64 > max_out {
                    return Err(ZlibError::TooBig(max_out));
                }
            }
            Err(e) => return Err(ZlibError::Corrupt(e.to_string())),
        }
    }
}
