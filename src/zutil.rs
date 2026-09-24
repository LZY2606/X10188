use flate2::{Decompress, FlushDecompress, Status};

/// 解压一个 zlib 流，输出超过 cap 立即中止（用于在解压中途发现大小欺骗）。
/// 返回 (输出字节, 在输入中消耗的字节数——即 zlib 边界)。
pub fn decompress_bounded(input: &[u8], cap: usize) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 65536];
    loop {
        let in_before = d.total_in();
        let out_before = d.total_out();
        let status = d
            .decompress(
                &input[in_before as usize..],
                &mut chunk,
                FlushDecompress::None,
            )
            .map_err(|e| format!("zlib 数据损坏: {e}"))?;
        let produced = (d.total_out() - out_before) as usize;
        out.extend_from_slice(&chunk[..produced]);
        if out.len() > cap {
            return Err(format!(
                "解压输出 {} 字节超过声明大小 {}（大小欺骗/截断）",
                out.len(),
                cap
            ));
        }
        match status {
            Status::StreamEnd => {
                return Ok((out, d.total_in() as usize));
            }
            Status::Ok | Status::BufError => {
                if d.total_in() == in_before && produced == 0 {
                    return Err("zlib 流未正常结束（输入耗尽或截断）".into());
                }
            }
        }
    }
}
