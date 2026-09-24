/// Zlib decompression with exact input-boundary reporting.
/// Returns (decompressed bytes, number of input bytes consumed by the stream).
pub fn decompress_with_boundary(input: &[u8], max_out: u64) -> Result<(Vec<u8>, usize), String> {
    let mut d = flate2::Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 65_536];
    loop {
        let in_before = d.total_in() as usize;
        let out_before = d.total_out() as usize;
        if in_before >= input.len() {
            return Err("zlib 流提前截断：需要更多输入但数据已耗尽".to_string());
        }
        let status = d
            .decompress(&input[in_before..], &mut buf, flate2::FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {e}"))?;
        let produced = d.total_out() as usize - out_before;
        out.extend_from_slice(&buf[..produced]);
        if out.len() as u64 > max_out {
            return Err(format!("解压输出 {} 超过上限 {}", out.len(), max_out));
        }
        match status {
            flate2::Status::StreamEnd => {
                return Ok((out, d.total_in() as usize));
            }
            flate2::Status::Ok => {
                if d.total_in() as usize == in_before && produced == 0 {
                    return Err("zlib 流停滞：无输入消耗也无输出".to_string());
                }
            }
            flate2::Status::BufError => {
                if d.total_in() as usize >= input.len() {
                    return Err("zlib 流在流结束前截断（BufError）".to_string());
                }
            }
        }
    }
}

pub fn compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}
