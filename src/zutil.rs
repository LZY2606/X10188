use flate2::{Decompress, FlushDecompress, Status};

pub struct Inflated {
    pub data: Vec<u8>,
    pub consumed: usize,
}

/// 解压 zlib 流, 同时返回该流在输入缓冲区中消耗的精确字节数 (zlib 边界检测)。
pub fn inflate_bounded(input: &[u8]) -> Result<Inflated, String> {
    let mut d = Decompress::new(true);
    let mut buf = vec![0u8; 8192];
    let mut produced = 0usize;
    loop {
        let consumed_so_far = d.total_in() as usize;
        if consumed_so_far > input.len() {
            return Err("zlib over-read".to_string());
        }
        let status = d
            .decompress(
                &input[consumed_so_far..],
                &mut buf[produced..],
                FlushDecompress::None,
            )
            .map_err(|e| format!("zlib: {e}"))?;
        produced = d.total_out() as usize;
        match status {
            Status::StreamEnd => {
                return Ok(Inflated {
                    data: buf[..produced].to_vec(),
                    consumed: d.total_in() as usize,
                });
            }
            Status::Ok => {
                if produced == buf.len() {
                    buf.resize(buf.len() * 2, 0);
                }
            }
            Status::BufError => {
                if produced == buf.len() {
                    buf.resize(buf.len() * 2, 0);
                } else {
                    return Err("truncated zlib stream".to_string());
                }
            }
        }
    }
}
