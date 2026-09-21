use flate2::{Decompress, FlushDecompress, Status};

/// Inflate a zlib stream, expecting exactly `expected` output bytes.
/// Returns (output, consumed_input_bytes) — consumed is the zlib boundary.
/// Detects size spoofing: stream ending early/late relative to declared size.
pub fn inflate_bounded(input: &[u8], expected: u64) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = 0usize;
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let mut chunk = [0u8; 65536];
        let status = d
            .decompress(&input[in_pos..], &mut chunk, FlushDecompress::None)
            .map_err(|e| format!("zlib 数据损坏: {}", e))?;
        let produced = (d.total_out() - before_out) as usize;
        out.extend_from_slice(&chunk[..produced]);
        in_pos = d.total_in() as usize;
        if out.len() as u64 > expected {
            return Err(format!(
                "大小欺骗: 声明 {} 字节, 解压已超过 {} 字节",
                expected,
                out.len()
            ));
        }
        match status {
            Status::StreamEnd => break,
            _ => {
                let progressed = d.total_in() != before_in || d.total_out() != before_out;
                if !progressed {
                    if in_pos >= input.len() {
                        return Err(format!(
                            "zlib 流截断: 声明 {} 字节, 仅解压出 {} 字节",
                            expected,
                            out.len()
                        ));
                    }
                    return Err("zlib 流无法继续推进".to_string());
                }
            }
        }
    }
    if out.len() as u64 != expected {
        return Err(format!(
            "大小欺骗: 声明 {} 字节, 实际解压 {} 字节",
            expected,
            out.len()
        ));
    }
    Ok((out, in_pos))
}

/// Inflate a zlib stream to its end, up to `cap` bytes. Returns (output, consumed).
pub fn inflate_all(input: &[u8], cap: u64) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = 0usize;
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let mut chunk = [0u8; 65536];
        let status = d
            .decompress(&input[in_pos..], &mut chunk, FlushDecompress::None)
            .map_err(|e| format!("zlib 数据损坏: {}", e))?;
        let produced = (d.total_out() - before_out) as usize;
        out.extend_from_slice(&chunk[..produced]);
        in_pos = d.total_in() as usize;
        if out.len() as u64 > cap {
            return Err(format!("解压超出上限 {} 字节", cap));
        }
        match status {
            Status::StreamEnd => break,
            _ => {
                let progressed = d.total_in() != before_in || d.total_out() != before_out;
                if !progressed {
                    return Err(format!(
                        "zlib 流截断: 已解压 {} 字节, 输入消耗 {}",
                        out.len(),
                        in_pos
                    ));
                }
            }
        }
    }
    Ok((out, in_pos))
}
