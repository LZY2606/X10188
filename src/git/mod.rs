mod crc;
pub mod delta;
mod index;
mod loose;
mod pack;

pub use delta::{apply_delta, DeltaBudget, DeltaError, DeltaStep};
pub use index::{parse_index, IndexEntry, IndexFile};
pub use loose::parse_loose;
pub use pack::{parse_pack, EntryRecord, PackEntry, PackFile, ParsedEntry};

use sha1::{Digest, Sha1};

pub const HARD_DECOMPRESS_LIMIT: usize = 64 * 1024 * 1024;
pub const PACK_SIGNATURE: [u8; 4] = *b"PACK";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
    Unknown(u8),
}

impl ObjectType {
    pub fn from_pack(value: u8) -> Self {
        match value {
            1 => ObjectType::Commit,
            2 => ObjectType::Tree,
            3 => ObjectType::Blob,
            4 => ObjectType::Tag,
            6 => ObjectType::OfsDelta,
            7 => ObjectType::RefDelta,
            other => ObjectType::Unknown(other),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjectType::Commit => "commit",
            ObjectType::Tree => "tree",
            ObjectType::Blob => "blob",
            ObjectType::Tag => "tag",
            ObjectType::OfsDelta => "ofs-delta",
            ObjectType::RefDelta => "ref-delta",
            ObjectType::Unknown(_) => "unknown",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "commit" => Some(ObjectType::Commit),
            "tree" => Some(ObjectType::Tree),
            "blob" => Some(ObjectType::Blob),
            "tag" => Some(ObjectType::Tag),
            _ => None,
        }
    }

    pub fn is_full(self) -> bool {
        matches!(
            self,
            ObjectType::Commit | ObjectType::Tree | ObjectType::Blob | ObjectType::Tag
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitError {
    Truncated(String),
    BadSignature(String),
    Unsupported(String),
    BadValue(String),
    Decompress(String),
    SizeSpoof { declared: usize, actual: usize },
    CrcMismatch { expected: u32, actual: u32 },
    ChecksumMismatch { expected: String, actual: String },
    BadObject(String),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitError::Truncated(msg) => write!(f, "truncated input: {msg}"),
            GitError::BadSignature(msg) => write!(f, "bad signature: {msg}"),
            GitError::Unsupported(msg) => write!(f, "unsupported: {msg}"),
            GitError::BadValue(msg) => write!(f, "bad value: {msg}"),
            GitError::Decompress(msg) => write!(f, "zlib decompression failed: {msg}"),
            GitError::SizeSpoof { declared, actual } => {
                write!(f, "size spoof: header says {declared}, stream ends at {actual}")
            }
            GitError::CrcMismatch { expected, actual } => write!(
                f,
                "CRC mismatch: index expects {expected:08x}, packed bytes hash to {actual:08x}"
            ),
            GitError::ChecksumMismatch { expected, actual } => {
                write!(f, "SHA-1 checksum mismatch: expected {expected}, actual {actual}")
            }
            GitError::BadObject(msg) => write!(f, "bad object: {msg}"),
        }
    }
}

impl std::error::Error for GitError {}

#[derive(Debug, Clone)]
pub struct ZlibResult {
    pub data: Vec<u8>,
    pub input_consumed: usize,
    pub output_end: usize,
}

pub fn object_id(kind: ObjectType, content: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(kind.name().as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update([0]);
    hasher.update(content);
    hasher.finalize().into()
}

pub fn hex_oid(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn parse_oid(value: &str) -> Result<[u8; 20], GitError> {
    let bytes = hex::decode(value).map_err(|err| GitError::BadValue(err.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| GitError::BadValue("object id must be 20 bytes".to_string()))
}

pub fn read_pack_size(bytes: &[u8], start: usize) -> Result<(usize, usize), GitError> {
    let first = *bytes
        .get(start)
        .ok_or_else(|| GitError::Truncated("object size header".into()))?;
    let mut size = (first & 0x0f) as usize;
    let mut shift = 4;
    let mut pos = start + 1;
    let mut current = first;
    while current & 0x80 != 0 {
        current = *bytes
            .get(pos)
            .ok_or_else(|| GitError::Truncated("continuation size byte".into()))?;
        size |= ((current & 0x7f) as usize) << shift;
        shift += 7;
        pos += 1;
        if shift > 63 {
            return Err(GitError::BadValue("object size is too large".into()));
        }
    }
    Ok((size, pos))
}

pub fn encode_pack_size(kind: u8, size: usize) -> Vec<u8> {
    let mut bytes = vec![kind << 4 | (size as u8 & 0x0f) | 0x80];
    let mut rest = size >> 4;
    while rest > 0 {
        let next = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest > 0 {
            bytes.push(next | 0x80);
        } else {
            bytes.push(next);
        }
    }
    if bytes.len() == 1 {
        bytes[0] &= 0x7f;
    }
    bytes
}

pub fn encode_ofs_distance(distance: usize) -> Vec<u8> {
    let mut value = distance;
    let mut bytes = vec![(value & 0x7f) as u8];
    value >>= 7;
    while value > 0 {
        value -= 1;
        bytes.push(((value & 0x7f) as u8) | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    bytes
}

pub fn decode_ofs_distance(bytes: &[u8], start: usize) -> Result<(usize, usize), GitError> {
    let first = *bytes
        .get(start)
        .ok_or_else(|| GitError::Truncated("ofs-delta distance".into()))?;
    let mut distance = (first & 0x7f) as usize;
    let mut pos = start + 1;
    let mut current = first;
    while current & 0x80 != 0 {
        current = *bytes
            .get(pos)
            .ok_or_else(|| GitError::Truncated("ofs-delta continuation".into()))?;
        distance = ((distance + 1) << 7) | (current & 0x7f) as usize;
        pos += 1;
    }
    Ok((distance, pos))
}

pub fn inflate_zlib_at(
    bytes: &[u8],
    start: usize,
    declared_size: Option<usize>,
    hard_limit: usize,
) -> Result<ZlibResult, GitError> {
    use flate2::{Decompress, FlushDecompress};

    let mut decompressor = Decompress::new(true);
    let mut output = Vec::new();
    let mut output_before = 0;
    loop {
        output.resize(output.len() + 8192, 0);
        let in_before = decompressor.total_in();
        let out_before = decompressor.total_out();
        let input = &bytes[start + in_before as usize..];
        let span = &mut output[out_before as usize..];
        let status = decompressor
            .decompress(input, span, FlushDecompress::None)
            .map_err(|err| GitError::Decompress(err.to_string()))?;
        let written = (decompressor.total_out() - out_before) as usize;
        output.truncate(out_before as usize + written);
        output_before = decompressor.total_out() as usize;
        if output_before > hard_limit {
            return Err(GitError::BadObject(format!(
                "decompressed output exceeds hard limit {hard_limit}"
            )));
        }
        if status == flate2::Status::StreamEnd {
            break;
        }
        let consumed = (decompressor.total_in() - in_before) as usize;
        if consumed == 0 && written == 0 {
            return Err(GitError::Decompress("decompressor made no progress".into()));
        }
    }
    if let Some(declared) = declared_size {
        if output.len() != declared {
            return Err(GitError::SizeSpoof {
                declared,
                actual: output.len(),
            });
        }
    }
    Ok(ZlibResult {
        data: output,
        output_end: output_before,
        input_consumed: decompressor.total_in() as usize,
    })
}

pub fn preview_text(bytes: &[u8], limit: usize) -> String {
    let sample = &bytes[..bytes.len().min(limit)];
    String::from_utf8_lossy(sample).replace('\0', "\\0")
}
