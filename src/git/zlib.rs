//! zlib 流边界识别：一次解压直到 StreamEnd，同时返回消耗的压缩字节数。

use flate2::{Decompress, FlushDecompress, Status};

/// 从 `data[start..]` 解压一个完整 zlib 流。
/// 返回 (解压输出, 消耗的输入字节数)。输出超过 max_out 时报错。
pub fn inflate_to_end(
    data: &[u8],
    start: usize,
    max_out: usize,
) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut result: Vec<u8> = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let in_before = d.total_in() as usize;
        let out_before = d.total_out() as usize;
        let status = d
            .decompress_vec(
                &data[start + in_before..],
                &mut buf,
                FlushDecompress::None,
            )
            .map_err(|e| format!("zlib 解压失败: {}", e))?;
        let produced = d.total_out() as usize - out_before;
        result.extend_from_slice(&buf[..produced]);
        if result.len() > max_out {
            return Err(format!(
                "解压输出 {} 字节超过单对象上限 {}（疑似 zip bomb / 大小欺骗）",
                result.len(),
                max_out
            ));
        }
        match status {
            Status::StreamEnd => {
                return Ok((result, d.total_in() as usize));
            }
            Status::Ok => {
                let consumed = d.total_in() as usize - in_before;
                if consumed == 0 && produced == 0 {
                    return Err("zlib 流意外结束（解压到一半数据缺失）".to_string());
                }
            }
            Status::BufError => {
                return Err("zlib BufError：压缩流损坏".to_string());
            }
        }
    }
}

/// 压缩一段数据为 zlib 流（供测试与打包使用）。
pub fn deflate_bytes(data: &[u8]) -> Vec<u8> {
    use flate2::{write::ZlibEncoder, Compression};
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}
