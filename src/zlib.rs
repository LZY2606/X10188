use flate2::{Decompress, FlushDecompress, Status};
use serde::Serialize;

/// 单对象解压硬上限，防止伪造巨大尺寸耗尽内存
pub const HARD_INFLATE_CAP: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub enum InflateError {
    Corrupt(String),
    Truncated,
    /// 声明大小与实际解压大小不一致（大小欺骗）
    SizeSpoof { declared: u64, actual: u64 },
    TooLarge { declared: u64 },
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InflateError::Corrupt(e) => write!(f, "zlib 数据损坏: {e}"),
            InflateError::Truncated => write!(f, "zlib 流被截断"),
            InflateError::SizeSpoof { declared, actual } => {
                write!(f, "大小欺骗: 声明 {declared} 字节, 实际解压 {actual} 字节")
            }
            InflateError::TooLarge { declared } => write!(f, "声明大小 {declared} 超过硬上限"),
        }
    }
}

/// 解压一段 zlib 流，返回 (解压结果, 消耗的输入字节数)。
/// 消耗的字节数即 zlib 边界，用于定位 pack 中下一个对象。
/// 严格校验解压结果长度等于 declared_size，否则报大小欺骗。
pub fn inflate_zlib(input: &[u8], declared_size: u64) -> Result<(Vec<u8>, usize), InflateError> {
    if declared_size > HARD_INFLATE_CAP {
        return Err(InflateError::TooLarge { declared: declared_size });
    }
    let (out, consumed) = inflate_raw(input)?;
    if out.len() as u64 != declared_size {
        return Err(InflateError::SizeSpoof {
            declared: declared_size,
            actual: out.len() as u64,
        });
    }
    Ok((out, consumed))
}

/// 解压 zlib 流，不做大小校验（用于 loose object）。
pub fn inflate_all(input: &[u8]) -> Result<(Vec<u8>, usize), InflateError> {
    inflate_raw(input)
}

fn inflate_raw(input: &[u8]) -> Result<(Vec<u8>, usize), InflateError> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let status = d
            .decompress(input, &mut chunk, FlushDecompress::None)
            .map_err(|e| InflateError::Corrupt(e.to_string()))?;
        let produced = (d.total_out() - before_out) as usize;
        out.extend_from_slice(&chunk[..produced]);
        if out.len() as u64 > HARD_INFLATE_CAP {
            return Err(InflateError::TooLarge {
                declared: out.len() as u64,
            });
        }
        match status {
            Status::StreamEnd => break,
            Status::Ok => {
                if d.total_in() == before_in && produced == 0 {
                    return Err(InflateError::Truncated);
                }
            }
            Status::BufError => return Err(InflateError::Truncated),
        }
    }
    Ok((out, d.total_in() as usize))
}
