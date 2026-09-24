use flate2::{Decompress, FlushDecompress, Status};

/// 解析期解压上限，防止解压炸弹在解析阶段耗尽内存
pub const MAX_INFLATE: usize = 256 * 1024 * 1024;

/// 解压一段 zlib 流，返回 (解压结果, 消耗的输入字节数)。
/// 消耗的输入字节数即 zlib 边界，用于定位 pack 中下一个对象。
pub fn decompress_bound(input: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out = Vec::new();
    let mut buf = [0u8; 65536];
    loop {
        let in_before = d.total_in() as usize;
        let out_before = d.total_out() as usize;
        if in_before >= input.len() {
            return Err("zlib 流截断：输入耗尽但流未结束".to_string());
        }
        let status = d
            .decompress(&input[in_before..], &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let produced = d.total_out() as usize - out_before;
        out.extend_from_slice(&buf[..produced]);
        if out.len() > MAX_INFLATE {
            return Err(format!("解压结果超过解析上限 {} 字节", MAX_INFLATE));
        }
        match status {
            Status::StreamEnd => return Ok((out, d.total_in() as usize)),
            _ => {
                if d.total_in() as usize == in_before && produced == 0 {
                    return Err("zlib 流无进展（数据可能截断）".to_string());
                }
            }
        }
    }
}

/// 压缩为 zlib 流（供测试与工具构造数据使用）
pub fn compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), Compression::fast());
    e.write_all(data).expect("zlib compress");
    e.finish().expect("zlib finish")
}
