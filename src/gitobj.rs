use sha1::{Digest, Sha1};

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(t: u8) -> &'static str {
    match t {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs_delta",
        OBJ_REF_DELTA => "ref_delta",
        _ => "unknown",
    }
}

pub fn is_delta(t: u8) -> bool {
    t == OBJ_OFS_DELTA || t == OBJ_REF_DELTA
}

/// 重新计算 Git object id: sha1("<type> <len>\0" + content)
pub fn object_id(type_name: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}", type_name, content.len()).as_bytes());
    h.update([0u8]);
    h.update(content);
    hex::encode(h.finalize())
}

#[derive(Debug)]
pub enum InflateError {
    Truncated,
    Corrupt(String),
    TooLarge { cap: u64 },
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InflateError::Truncated => write!(f, "zlib 流被截断"),
            InflateError::Corrupt(e) => write!(f, "zlib 数据损坏: {}", e),
            InflateError::TooLarge { cap } => write!(f, "解压输出超过硬上限 {} 字节", cap),
        }
    }
}

pub struct Inflated {
    pub data: Vec<u8>,
    /// zlib 流消耗的输入字节数，即 zlib 边界
    pub consumed: usize,
}

/// 流式解压一段 zlib 数据，返回解压结果与 zlib 边界（消耗的输入字节数）。
/// 不预先信任任何声明大小，解压到 StreamEnd 为止，由调用方比对声明大小以发现大小欺骗。
pub fn inflate_stream(data: &[u8], hard_cap: u64) -> Result<Inflated, InflateError> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut d = Decompress::new(true);
    let mut out = Vec::new();
    let mut chunk = vec![0u8; 16384];
    loop {
        let in_before = d.total_in() as usize;
        if in_before > data.len() {
            return Err(InflateError::Truncated);
        }
        let out_before = d.total_out() as usize;
        let status = d
            .decompress(&data[in_before..], &mut chunk, FlushDecompress::None)
            .map_err(|e| InflateError::Corrupt(e.to_string()))?;
        let produced = d.total_out() as usize - out_before;
        out.extend_from_slice(&chunk[..produced]);
        if out.len() as u64 > hard_cap {
            return Err(InflateError::TooLarge { cap: hard_cap });
        }
        match status {
            Status::StreamEnd => break,
            _ => {
                if (d.total_in() as usize) >= data.len() && produced == 0 {
                    return Err(InflateError::Truncated);
                }
            }
        }
    }
    Ok(Inflated {
        data: out,
        consumed: d.total_in() as usize,
    })
}

/// 完整解压（用于 loose object），要求恰好消耗全部输入。
pub fn inflate_all(data: &[u8], hard_cap: u64) -> Result<Vec<u8>, InflateError> {
    let inf = inflate_stream(data, hard_cap)?;
    Ok(inf.data)
}
