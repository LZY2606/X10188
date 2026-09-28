use flate2::{Decompress, FlushCompress, FlushDecompress};
use sha1::{Digest, Sha1};

pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for i in 0..256u32 {
        let mut c = i;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
        }
        table[i as usize] = c;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

pub fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    let d = h.finalize();
    let mut s = String::with_capacity(40);
    for b in d {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn git_oid(obj_type: &str, content: &[u8]) -> String {
    let mut store: Vec<u8> = Vec::with_capacity(content.len() + 32);
    store.extend_from_slice(obj_type.as_bytes());
    store.push(b' ');
    store.extend_from_slice(content.len().to_string().as_bytes());
    store.push(0);
    store.extend_from_slice(content);
    sha1_hex(&store)
}

pub fn read_size_encoding(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut shift = 0u32;
    let mut result = 0u64;
    loop {
        if *pos >= data.len() {
            return Err("size encoding truncated".into());
        }
        let byte = data[*pos];
        *pos += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("size encoding too long".into());
        }
    }
    Ok(result)
}

pub fn write_size_encoding(mut size: u64, out: &mut Vec<u8>) {
    let mut bytes = vec![(size & 0x7f) as u8];
    size >>= 7;
    while size > 0 {
        let last = bytes.last_mut().unwrap();
        *last |= 0x80;
        bytes.push((size & 0x7f) as u8);
        size >>= 7;
    }
    out.extend_from_slice(&bytes);
}

pub fn encode_ofs_distance(distance: u64) -> Vec<u8> {
    assert!(distance >= 1, "ofs distance must be positive");
    let mut bytes = vec![(distance & 0x7f) as u8];
    let mut rest = distance >> 7;
    while rest > 0 {
        let last = bytes.last_mut().unwrap();
        *last |= 0x80;
        bytes.push(0x80 | ((rest - 1) & 0x7f) as u8);
        rest = (rest - 1) >> 7;
    }
    bytes.reverse();
    bytes
}

pub fn read_ofs_distance(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    if *pos >= data.len() {
        return Err("ofs distance truncated".into());
    }
    let mut byte = data[*pos];
    *pos += 1;
    let mut value = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        if *pos >= data.len() {
            return Err("ofs distance truncated".into());
        }
        byte = data[*pos];
        *pos += 1;
        value = ((value + 1) << 7) | (byte & 0x7f) as u64;
    }
    Ok(value)
}

#[derive(Debug, Clone)]
pub struct InflateResult {
    pub data: Vec<u8>,
    pub consumed: usize,
}

#[derive(Debug, Clone)]
pub enum InflateError {
    Zlib(String),
    DeclaredTooSmall {
        declared: u64,
        actual: u64,
        result: InflateResult,
    },
    DeclaredTooLarge {
        declared: u64,
        actual: u64,
        result: InflateResult,
    },
    HardLimit(u64),
}

impl InflateError {
    pub fn message(&self) -> String {
        match self {
            InflateError::Zlib(s) => format!("zlib error: {}", s),
            InflateError::DeclaredTooSmall { declared, actual } => {
                format!("size spoof: declared {}, actual inflated {}", declared, actual)
            }
            InflateError::DeclaredTooLarge { declared, actual } => {
                format!("size spoof: declared {}, stream ended at {}", declared, actual)
            }
            InflateError::HardLimit(limit) => format!("hard inflation limit {} exceeded", limit),
        }
    }
}

pub fn inflate_at(
    data: &[u8],
    start: usize,
    declared_size: Option<u64>,
    hard_limit: u64,
) -> Result<InflateResult, InflateError> {
    let mut decomp = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let input = &data[start..];
    let mut in_consumed = 0usize;
    loop {
        if out.len() as u64 > hard_limit {
            return Err(InflateError::HardLimit(hard_limit));
        }
        let chunk = &input[in_consumed..];
        let before_in = decomp.total_in();
        let before_out = decomp.total_out();
        let cap = out.len();
        out.resize(cap + 65536, 0);
        let status = decomp
            .decompress(chunk, &mut out[cap..], FlushDecompress::None)
            .map_err(|e| InflateError::Zlib(e.to_string()))?;
        in_consumed += (decomp.total_in() - before_in) as usize;
        let got = (decomp.total_out() - before_out) as usize;
        out.truncate(cap + got);
        match status {
            flate2::Status::StreamEnd => break,
            flate2::Status::Ok | flate2::Status::BufError => {
                if chunk.is_empty() && got == 0 {
                    return Err(InflateError::Zlib("stream truncated".into()));
                }
            }
        }
    }
    if let Some(declared) = declared_size {
        let actual = out.len() as u64;
        if actual < declared {
            return Err(InflateError::DeclaredTooLarge {
                declared,
                actual,
                result: InflateResult { data: out, consumed: in_consumed },
            });
        }
        if actual > declared {
            return Err(InflateError::DeclaredTooSmall {
                declared,
                actual,
                result: InflateResult { data: out, consumed: in_consumed },
            });
        }
    }
    Ok(InflateResult {
        data: out,
        consumed: in_consumed,
    })
}

pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut enc, data).unwrap();
    enc.finish().unwrap()
}

#[derive(Debug, Clone)]
pub struct DeltaHeader {
    pub base_size: u64,
    pub result_size: u64,
    pub header_len: usize,
}

pub fn read_delta_header(delta: &[u8]) -> Result<DeltaHeader, String> {
    let mut pos = 0;
    let base_size = read_size_encoding(delta, &mut pos)?;
    let after_base = pos;
    let result_size = read_size_encoding(delta, &mut pos)?;
    Ok(DeltaHeader {
        base_size,
        result_size,
        header_len: pos,
    })
}

#[derive(Debug, Clone)]
pub enum ApplyError {
    BadHeader(String),
    BaseSizeMismatch { declared: u64, actual: u64 },
    ZeroInsert,
    CopyOutOfRange { offset: u64, size: u64, base_len: u64 },
    InsertOutOfRange { len: usize, remaining: usize },
    Truncated,
    UnknownOpcode(u8),
    TrailingData,
    ResultSizeMismatch { declared: u64, actual: u64 },
    OutputLimit,
}

impl ApplyError {
    pub fn message(&self) -> String {
        match self {
            ApplyError::BadHeader(s) => format!("delta header: {}", s),
            ApplyError::BaseSizeMismatch { declared, actual } => {
                format!("base size spoof: header {}, actual base {}", declared, actual)
            }
            ApplyError::ZeroInsert => "zero-length insert opcode".into(),
            ApplyError::CopyOutOfRange { offset, size, base_len } => format!(
                "copy out of range: offset={} size={} base_len={}",
                offset, size, base_len
            ),
            ApplyError::InsertOutOfRange { len, remaining } => {
                format!("insert needs {} bytes but {} remain", len, remaining)
            }
            ApplyError::Truncated => "delta instructions truncated".into(),
            ApplyError::UnknownOpcode(b) => format!("unknown delta opcode 0x{:02x}", b),
            ApplyError::TrailingData => "trailing bytes after delta instructions".into(),
            ApplyError::ResultSizeMismatch { declared, actual } => {
                format!("result size spoof: header {}, actual output {}", declared, actual)
            }
            ApplyError::OutputLimit => "output budget exceeded".into(),
        }
    }
}

pub struct ApplyOutcome {
    pub output: Vec<u8>,
    pub instr_start: usize,
    pub instr_end: usize,
}

pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    output_limit: u64,
) -> Result<ApplyOutcome, ApplyError> {
    let header = read_delta_header(delta).map_err(ApplyError::BadHeader)?;
    if header.base_size != base.len() as u64 {
        return Err(ApplyError::BaseSizeMismatch {
            declared: header.base_size,
            actual: base.len() as u64,
        });
    }
    let mut output: Vec<u8> = Vec::with_capacity(header.result_size.min(output_limit) as usize);
    let mut pos = header.header_len;
    let instr_start = pos;
    while pos < delta.len() {
        let opcode = delta[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            let mut cp_off = 0u32;
            let mut cp_size = 0u32;
            if opcode & 0x01 != 0 {
                cp_off |= delta.get(pos).copied().ok_or(ApplyError::Truncated)? as u32;
                pos += 1;
            }
            if opcode & 0x02 != 0 {
                cp_off |= (*delta.get(pos).ok_or(ApplyError::Truncated)? as u32) << 8;
                pos += 1;
            }
            if opcode & 0x04 != 0 {
                cp_off |= (*delta.get(pos).ok_or(ApplyError::Truncated)? as u32) << 16;
                pos += 1;
            }
            if opcode & 0x08 != 0 {
                cp_off |= (*delta.get(pos).ok_or(ApplyError::Truncated)? as u32) << 24;
                pos += 1;
            }
            if opcode & 0x10 != 0 {
                cp_size |= *delta.get(pos).ok_or(ApplyError::Truncated)? as u32;
                pos += 1;
            }
            if opcode & 0x20 != 0 {
                cp_size |= (*delta.get(pos).ok_or(ApplyError::Truncated)? as u32) << 16;
                pos += 1;
            }
            if opcode & 0x40 != 0 {
                cp_size |= (*delta.get(pos).ok_or(ApplyError::Truncated)? as u32) << 24;
                pos += 1;
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let start = cp_off as u64;
            let size = cp_size as u64;
            if start + size > base.len() as u64 {
                return Err(ApplyError::CopyOutOfRange {
                    offset: start,
                    size,
                    base_len: base.len() as u64,
                });
            }
            if output.len() as u64 + size > output_limit {
                return Err(ApplyError::OutputLimit);
            }
            output.extend_from_slice(&base[start as usize..(start + size) as usize]);
        } else if opcode != 0 {
            let len = opcode as usize;
            if pos + len > delta.len() {
                return Err(ApplyError::InsertOutOfRange {
                    len,
                    remaining: delta.len() - pos,
                });
            }
            if output.len() as u64 + len as u64 > output_limit {
                return Err(ApplyError::OutputLimit);
            }
            output.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
        } else {
            return Err(ApplyError::UnknownOpcode(0));
        }
    }
    let instr_end = pos;
    if output.len() as u64 != header.result_size {
        return Err(ApplyError::ResultSizeMismatch {
            declared: header.result_size,
            actual: output.len() as u64,
        });
    }
    Ok(ApplyOutcome {
        output,
        instr_start,
        instr_end,
    })
}

#[allow(dead_code)]
fn _flush_note(_f: FlushCompress) {}
