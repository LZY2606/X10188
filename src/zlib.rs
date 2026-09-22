//! 流式 zlib 解压：精确报告压缩流边界（consumed 字节数），
//! 并在解压过程中检测“声明大小欺骗”（输出超过或不足声明大小）。

use flate2::{Decompress, FlushDecompress, Status};

/// 防御性上限：声明大小超过该值直接视为异常，避免巨额分配。
pub const MAX_DECLARED: u64 = 1 << 31;

#[derive(Debug)]
pub enum ZlibError {
    Corrupt(String),
    /// 声明的大小与实际解压输出不符（解压到一半才发现也算）。
    SizeFraud { declared: u64, got: u64 },
}

impl std::fmt::Display for ZlibError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZlibError::Corrupt(m) => write!(f, "zlib 流损坏: {m}"),
            ZlibError::SizeFraud { declared, got } => {
                write!(f, "大小欺骗: 声明 {declared} 字节, 实际解压 {got} 字节")
            }
        }
    }
}

pub struct Inflated {
    pub data: Vec<u8>,
    /// 消耗的输入字节数 = zlib 流边界，下一个 pack 条目从这里开始。
    pub consumed: usize,
}

/// 按 pack 条目头中声明的大小解压；多一个字节或少一个字节都算欺骗。
pub fn inflate_bounded(input: &[u8], declared: u64) -> Result<Inflated, ZlibError> {
    if declared > MAX_DECLARED {
        return Err(ZlibError::SizeFraud { declared, got: 0 });
    }
    let cap = declared as usize;
    let mut d = Decompress::new(true);
    // 多分配 1 字节：如果输出填满仍未到流尾，说明实际数据比声明的多。
    let mut out = vec![0u8; cap + 1];
    let mut in_pos = 0usize;
    let mut out_pos = 0usize;
    loop {
        let status = d
            .decompress(&input[in_pos..], &mut out[out_pos..], FlushDecompress::None)
            .map_err(|e| ZlibError::Corrupt(e.to_string()))?;
        in_pos = d.total_in() as usize;
        out_pos = d.total_out() as usize;
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if out_pos > cap {
                    return Err(ZlibError::SizeFraud { declared, got: out_pos as u64 });
                }
                if out_pos == out.len() {
                    return Err(ZlibError::SizeFraud { declared, got: out_pos as u64 + 1 });
                }
                if in_pos >= input.len() {
                    return Err(ZlibError::Corrupt("zlib 流被截断".into()));
                }
            }
        }
    }
    if out_pos != cap {
        return Err(ZlibError::SizeFraud { declared, got: out_pos as u64 });
    }
    out.truncate(out_pos);
    Ok(Inflated { data: out, consumed: in_pos })
}

/// 解压 loose object（大小未知，解析头部后再校验），cap 为防御上限。
pub fn inflate_loose(input: &[u8], cap: u64) -> Result<Inflated, ZlibError> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = 0usize;
    loop {
        let mut chunk = vec![0u8; 65536];
        let status = d
            .decompress(&input[in_pos..], &mut chunk, FlushDecompress::None)
            .map_err(|e| ZlibError::Corrupt(e.to_string()))?;
        let produced = d.total_out() as usize - out.len();
        chunk.truncate(produced);
        out.extend_from_slice(&chunk);
        in_pos = d.total_in() as usize;
        if out.len() as u64 > cap {
            return Err(ZlibError::SizeFraud { declared: cap, got: out.len() as u64 });
        }
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if in_pos >= input.len() {
                    return Err(ZlibError::Corrupt("zlib 流被截断".into()));
                }
            }
        }
    }
    Ok(Inflated { data: out, consumed: in_pos })
}
