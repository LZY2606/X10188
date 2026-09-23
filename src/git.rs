use flate2::Decompress;
use sha1::{Digest, Sha1};
use std::fmt;

pub const MAX_DECLARED: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjectType {
    pub fn name(self) -> &'static str {
        match self {
            ObjectType::Commit => "commit",
            ObjectType::Tree => "tree",
            ObjectType::Blob => "blob",
            ObjectType::Tag => "tag",
            ObjectType::OfsDelta => "ofs-delta",
            ObjectType::RefDelta => "ref-delta",
        }
    }

    pub fn base_name(self) -> Option<&'static str> {
        match self {
            ObjectType::Commit => Some("commit"),
            ObjectType::Tree => Some("tree"),
            ObjectType::Blob => Some("blob"),
            ObjectType::Tag => Some("tag"),
            ObjectType::OfsDelta | ObjectType::RefDelta => None,
        }
    }
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitObject {
    pub kind: ObjectType,
    pub data: Vec<u8>,
}

impl GitObject {
    pub fn new(kind: ObjectType, data: Vec<u8>) -> Self {
        Self { kind, data }
    }

    pub fn git_oid(&self) -> [u8; 20] {
        let mut hasher = Sha1::new();
        hasher.update(self.kind.name().as_bytes());
        hasher.update(b" ");
        hasher.update(self.data.len().to_string().as_bytes());
        hasher.update([0]);
        hasher.update(&self.data);
        hasher.finalize().into()
    }
}

#[derive(Debug)]
pub struct ZStream {
    pub data: Vec<u8>,
    pub consumed: usize,
    pub declared: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GitError {
    Truncated(&'static str),
    BadHeader(String),
    BadZlib(String),
    SizeMismatch { declared: usize, actual: usize },
    BadDelta(String),
    Unsupported(String),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::Truncated(what) => write!(f, "truncated {what}"),
            GitError::BadHeader(msg) => write!(f, "bad header: {msg}"),
            GitError::BadZlib(msg) => write!(f, "bad zlib stream: {msg}"),
            GitError::SizeMismatch { declared, actual } => {
                write!(f, "declared size {declared}, actual size {actual}")
            }
            GitError::BadDelta(msg) => write!(f, "bad delta: {msg}"),
            GitError::Unsupported(msg) => write!(f, "unsupported: {msg}"),
        }
    }
}

impl std::error::Error for GitError {}

pub fn read_size_encoding(input: &[u8], pos: &mut usize) -> Result<usize, GitError> {
    let mut shift = 0u32;
    let mut value = 0usize;
    loop {
        if *pos >= input.len() {
            return Err(GitError::Truncated("size encoding"));
        }
        let byte = input[*pos];
        *pos += 1;
        value |= ((byte & 0x7f) as usize)
            .checked_shl(shift)
            .ok_or_else(|| GitError::BadHeader("size overflow".into()))?;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Ok(value)
}

pub fn inflate_at(input: &[u8], start: usize) -> Result<ZStream, GitError> {
    let mut decoder = Decompress::new(true);
    let mut output = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress_vec(
                &input[start..],
                &mut chunk,
                flate2::FlushDecompress::None,
            )
            .map_err(|err| GitError::BadZlib(err.to_string()))?;
        let produced = (decoder.total_out() - before_out) as usize;
        output.extend_from_slice(&chunk[..produced]);
        if output.len() > MAX_DECLARED {
            return Err(GitError::BadZlib("inflated object exceeds hard limit".into()));
        }
        let consumed = (decoder.total_in() - before_in) as usize;
        if status == flate2::Status::StreamEnd {
            return Ok(ZStream {
                data: output,
                consumed,
                declared: None,
            });
        }
        if consumed == 0 && produced == 0 {
            return Err(GitError::BadZlib("decompressor made no progress".into()));
        }
    }
}

pub fn inflate_declared(input: &[u8], start: usize, declared: usize) -> Result<ZStream, GitError> {
    if declared > MAX_DECLARED {
        return Err(GitError::BadHeader("declared size exceeds hard limit".into()));
    }
    let stream = inflate_at(input, start)?;
    if stream.data.len() != declared {
        return Err(GitError::SizeMismatch {
            declared,
            actual: stream.data.len(),
        });
    }
    Ok(ZStream {
        declared: Some(declared),
        ..stream
    })
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffffffffu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xedb88320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

pub fn oid_hex(oid: &[u8; 20]) -> String {
    hex::encode(oid)
}

pub fn parse_oid(text: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(text).ok()?;
    bytes.try_into().ok()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeltaOp {
    pub index: i64,
    pub kind: String,
    pub offset: usize,
    pub length: usize,
    pub src_offset: Option<usize>,
    pub dst_offset: usize,
    pub size: usize,
}

pub fn parse_delta_ops(delta: &[u8]) -> Result<(usize, usize, Vec<DeltaOp>), GitError> {
    let mut pos = 0;
    let base_size = read_size_encoding(delta, &mut pos)?;
    let result_size = read_size_encoding(delta, &mut pos)?;
    let mut ops = Vec::new();
    let mut index = 0i64;
    let mut dst_offset = 0usize;
    while pos < delta.len() {
        let opcode_pos = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err(GitError::Truncated("copy offset"));
                    }
                    offset |= (delta[pos] as usize) << (8 * bit);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (4 + bit)) != 0 {
                    if pos >= delta.len() {
                        return Err(GitError::Truncated("copy size"));
                    }
                    size |= (delta[pos] as usize) << (8 * bit);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            ops.push(DeltaOp {
                index,
                kind: "copy".into(),
                offset: opcode_pos,
                length: pos - opcode_pos,
                src_offset: Some(offset),
                dst_offset,
                size,
            });
            dst_offset += size;
        } else if opcode > 0 {
            let take = opcode as usize;
            if pos + opcode as usize > delta.len() {
                return Err(GitError::Truncated("insert payload"));
            }
            ops.push(DeltaOp {
                index,
                kind: "insert".into(),
                offset: opcode_pos,
                length: 1 + take,
                src_offset: None,
                dst_offset,
                size: take,
            });
            dst_offset += take;
            pos += take;
        } else {
            return Err(GitError::BadDelta("opcode zero is reserved".into()));
        }
        index += 1;
    }
    Ok((base_size, result_size, ops))
}

pub struct AppliedDelta {
    pub output: Vec<u8>,
    pub base_size: usize,
    pub result_size: usize,
    pub ops: Vec<DeltaOp>,
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<AppliedDelta, GitError> {
    let mut pos = 0;
    let base_size = read_size_encoding(delta, &mut pos)?;
    let result_size = read_size_encoding(delta, &mut pos)?;
    if base_size != base.len() {
        return Err(GitError::BadDelta(format!(
            "base size header {base_size} does not match input {}",
            base.len()
        )));
    }
    if result_size > MAX_DECLARED {
        return Err(GitError::BadDelta("result exceeds hard limit".into()));
    }
    let mut output = Vec::with_capacity(result_size.min(MAX_DECLARED));
    let mut ops = Vec::new();
    let mut index = 0i64;
    while pos < delta.len() {
        let opcode_pos = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode & 0x80 != 0 {
            let mut copy_offset = 0usize;
            let mut copy_size = 0usize;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err(GitError::Truncated("copy offset"));
                    }
                    copy_offset |= (delta[pos] as usize) << (8 * bit);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (4 + bit)) != 0 {
                    if pos >= delta.len() {
                        return Err(GitError::Truncated("copy size"));
                    }
                    copy_size |= (delta[pos] as usize) << (8 * bit);
                    pos += 1;
                }
            }
            if copy_size == 0 {
                copy_size = 0x10000;
            }
            let end = copy_offset
                .checked_add(copy_size)
                .ok_or_else(|| GitError::BadDelta("copy range overflow".into()))?;
            if end > base.len() {
                return Err(GitError::BadDelta(format!(
                    "copy {copy_offset}+{copy_size} outside base of {}",
                    base.len()
                )));
            }
            output.extend_from_slice(&base[copy_offset..end]);
            ops.push(DeltaOp {
                index,
                kind: "copy".into(),
                offset: opcode_pos,
                length: pos - opcode_pos,
                src_offset: Some(copy_offset),
                dst_offset: output.len(),
                size: copy_size,
            });
        } else if opcode > 0 {
            let take = opcode as usize;
            if pos + take > delta.len() {
                return Err(GitError::Truncated("insert payload"));
            }
            output.extend_from_slice(&delta[pos..pos + take]);
            ops.push(DeltaOp {
                index,
                kind: "insert".into(),
                offset: opcode_pos,
                length: 1 + take,
                src_offset: None,
                dst_offset: output.len(),
                size: take,
            });
            pos += take;
        } else {
            return Err(GitError::BadDelta("opcode zero is reserved".into()));
        }
        index += 1;
    }
    if output.len() != result_size {
        return Err(GitError::SizeMismatch {
            declared: result_size,
            actual: output.len(),
        });
    }
    Ok(AppliedDelta {
        output,
        base_size,
        result_size,
        ops,
    })
}
