pub mod delta;
pub mod idx;
pub mod loose;
pub mod pack;
pub mod writer;

pub use pack::bounded_decompress as bounded_decompress_local;

use sha1::{Digest, Sha1};
use std::fmt;

#[derive(Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ObjectId([u8; 20]);

impl ObjectId {
    pub const ZERO: ObjectId = ObjectId([0; 20]);
    pub fn new(bytes: [u8; 20]) -> Self { Self(bytes) }
    pub fn as_bytes(&self) -> &[u8; 20] { &self.0 }
    pub fn from_hex(input: &str) -> Option<Self> {
        let bytes = hex::decode(input).ok()?;
        let bytes: [u8; 20] = bytes.try_into().ok()?;
        Some(Self(bytes))
    }
    pub fn hex(&self) -> String { hex::encode(self.0) }
}

impl fmt::Display for ObjectId { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.hex()) } }
impl fmt::Debug for ObjectId { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.hex()) } }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectType { Commit, Tree, Blob, Tag, OfsDelta, RefDelta }

impl ObjectType {
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Commit,
            2 => Self::Tree,
            3 => Self::Blob,
            4 => Self::Tag,
            6 => Self::OfsDelta,
            7 => Self::RefDelta,
            _ => return None,
        })
    }
    pub fn code(self) -> u8 {
        match self {
            Self::Commit => 1, Self::Tree => 2, Self::Blob => 3, Self::Tag => 4,
            Self::OfsDelta => 6, Self::RefDelta => 7,
        }
    }
    pub fn git_name(self) -> &'static str {
        match self {
            Self::Commit => "commit", Self::Tree => "tree", Self::Blob => "blob", Self::Tag => "tag",
            Self::OfsDelta | Self::RefDelta => "delta",
        }
    }
}

pub fn object_id(kind: ObjectType, data: &[u8]) -> ObjectId {
    let header = format!("{} {}\0", kind.git_name(), data.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(data);
    ObjectId::new(hasher.finalize().into())
}

pub fn encode_size(mut size: u64, first_shift: u32) -> Vec<u8> {
    let mut out = Vec::new();
    if first_shift == 4 {
        let mut first = (size as u8 & 0x0f) << 4;
        size >>= 4;
        if size != 0 { first |= 0x80; }
        out.push(first);
    }
    while size != 0 {
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 { byte |= 0x80; }
        out.push(byte);
    }
    if out.is_empty() { out.push(0); }
    out
}

pub fn read_size(bytes: &[u8], first_shift: u32) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let mut size = if first_shift == 4 { (first >> 4) as u64 } else { (first & 0x7f) as u64 };
    let mut shift = first_shift;
    let mut index = 1;
    let mut current = first;
    while current & 0x80 != 0 {
        current = *bytes.get(index)?;
        index += 1;
        size |= ((current & 0x7f) as u64) << shift;
        shift += 7;
    }
    Some((size, index))
}

pub fn read_delta_size(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut index = 0;
    loop {
        let mut byte = *bytes.get(index)?;
        index += 1;
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 { break; }
        shift += 7;
        if shift > 63 && byte != 0 { return None; }
    }
    Some((result, index))
}

pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut encoder = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}
