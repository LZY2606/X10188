use flate2::{Decompress, FlushDecompress, Status};

/// 从 data 起点解压一个 zlib 流, 返回 (内容, 压缩字节数)。
/// cap: 若给出, 解压输出一旦超过该上限立即报错 (用于中途发现大小欺骗)。
pub fn inflate_prefix(data: &[u8], cap: Option<u64>) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 65536];
    let mut pos = 0usize;
    loop {
        let in_before = d.total_in() as usize;
        let out_before = d.total_out() as usize;
        let status = d
            .decompress(&data[pos..], &mut chunk, FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let consumed = d.total_in() as usize - in_before;
        let produced = d.total_out() as usize - out_before;
        pos += consumed;
        out.extend_from_slice(&chunk[..produced]);
        if let Some(c) = cap {
            if out.len() as u64 > c {
                return Err(format!(
                    "大小欺骗: 解压到 {} 字节时已超过声明大小 {}",
                    out.len(),
                    c
                ));
            }
        }
        match status {
            Status::StreamEnd => return Ok((out, pos)),
            _ => {
                if consumed == 0 && produced == 0 {
                    return Err("zlib 流截断".into());
                }
            }
        }
    }
}
