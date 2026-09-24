//! zlib 流边界探测与限量解压（大小欺骗防护）。
use flate2::read::ZlibDecoder;
use std::io::Read;

pub const HARD_CAP: u64 = 1 << 30; // 1GiB 绝对上限，防 zip 炸弹

pub struct Inflated {
    pub data: Vec<u8>,
    /// zlib 流消耗的输入字节数（含 adler32），即流边界
    pub consumed: usize,
}

/// 从 data 开头解压一个 zlib 流，最多解压出 declared+1 字节。
/// 调用方用 (data.len() 与 declared 比较) 判定大小欺骗。
pub fn inflate_limited(data: &[u8], declared: u64) -> Result<Inflated, String> {
    let limit = declared.saturating_add(1).min(HARD_CAP);
    let mut dec = ZlibDecoder::new(data);
    let mut out = Vec::new();
    {
        let mut limited = (&mut dec).take(limit);
        limited
            .read_to_end(&mut out)
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
    }
    Ok(Inflated {
        data: out,
        consumed: dec.total_in() as usize,
    })
}
