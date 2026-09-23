//! 基础原语：SHA-1、Git object id、CRC32、zlib 边界感知解压。
use sha1::{Digest, Sha1};

pub const MAX_INFLATE: u64 = 256 * 1024 * 1024;

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    to_hex(&h.finalize())
}

/// Git object id = sha1("<type> <len>\\0" + content)
pub fn object_id(kind: &str, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", kind, content.len()).as_bytes());
    h.update(content);
    to_hex(&h.finalize())
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
        *slot = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

pub struct Inflated {
    pub data: Vec<u8>,
    pub consumed: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum InflateError {
    Truncated,
    Zlib(String),
    /// 输出超过上限（用于提前发现 pack 头里的大小欺骗）
    OutputExceeded { limit: usize },
}

impl std::fmt::Display for InflateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InflateError::Truncated => write!(f, "truncated zlib stream"),
            InflateError::Zlib(e) => write!(f, "zlib error: {e}"),
            InflateError::OutputExceeded { limit } => {
                write!(f, "inflated output exceeded limit {limit}")
            }
        }
    }
}

/// 解压 zlib 流并返回消耗的输入字节数（即压缩流边界）。
/// `max_out` 用于在解压到一半时发现声明大小欺骗并提前中止。
pub fn inflate(input: &[u8], max_out: Option<usize>) -> Result<Inflated, InflateError> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 32768];
    loop {
        let in_off = d.total_in() as usize;
        if in_off >= input.len() {
            return Err(InflateError::Truncated);
        }
        let before_out = d.total_out() as usize;
        let status = d
            .decompress(&input[in_off..], &mut buf, FlushDecompress::None)
            .map_err(|e| InflateError::Zlib(e.to_string()))?;
        let produced = d.total_out() as usize - before_out;
        if let Some(limit) = max_out {
            if out.len() + produced > limit {
                return Err(InflateError::OutputExceeded { limit });
            }
        }
        out.extend_from_slice(&buf[..produced]);
        match status {
            Status::StreamEnd => {
                return Ok(Inflated { data: out, consumed: d.total_in() as usize })
            }
            Status::Ok => {
                if produced == 0 {
                    return Err(InflateError::Truncated);
                }
            }
            Status::BufError => return Err(InflateError::Truncated),
        }
    }
}

/// 只扫描边界（丢弃输出），用于大小欺骗后仍定位下一个 entry。
pub fn inflate_consumed_only(input: &[u8]) -> Result<usize, InflateError> {
    use flate2::{Decompress, FlushDecompress, Status};
    let mut d = Decompress::new(true);
    let mut buf = [0u8; 32768];
    loop {
        let in_off = d.total_in() as usize;
        if in_off >= input.len() {
            return Err(InflateError::Truncated);
        }
        let status = d
            .decompress(&input[in_off..], &mut buf, FlushDecompress::None)
            .map_err(|e| InflateError::Zlib(e.to_string()))?;
        match status {
            Status::StreamEnd => return Ok(d.total_in() as usize),
            Status::Ok => {}
            Status::BufError => return Err(InflateError::Truncated),
        }
    }
}
