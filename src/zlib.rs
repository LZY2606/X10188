//! zlib 边界感知解压：返回解压结果与消耗的输入字节数（zlib 流边界）。

use flate2::{Decompress, FlushDecompress, Status};

/// 从 input 起始处解压一个 zlib 流。
/// 成功返回 (解压数据, 消耗的字节数)；失败返回错误描述（含已消耗偏移证据）。
pub fn inflate_bounded(input: &[u8]) -> Result<(Vec<u8>, usize), String> {
    inflate_bounded_cap(input, u64::MAX)
}

/// 带输出上限的版本：输出超过 max_out 时中止（用于预算/防伪）。
pub fn inflate_bounded_cap(input: &[u8], max_out: u64) -> Result<(Vec<u8>, usize), String> {
    let mut dec = Decompress::new(true);
    let mut buf = vec![0u8; 64 * 1024];
    let mut out: Vec<u8> = Vec::new();
    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let status = dec
            .decompress(&input[before_in as usize..], &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib 损坏（已消耗 {} 字节）: {}", before_in, e))?;
        let produced = (dec.total_out() - before_out) as usize;
        out.extend_from_slice(&buf[..produced]);
        if out.len() as u64 > max_out {
            return Err(format!("解压输出超过上限 {} 字节（大小欺骗嫌疑）", max_out));
        }
        match status {
            Status::StreamEnd => return Ok((out, dec.total_in() as usize)),
            _ => {
                if produced == 0 && dec.total_in() == before_in {
                    return Err(format!(
                        "zlib 流截断（已消耗 {} 字节，未到达流尾）",
                        dec.total_in()
                    ));
                }
            }
        }
    }
}
