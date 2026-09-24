use serde::Serialize;

pub const HARD_INFLATE_CAP: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ObjKind {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl ObjKind {
    pub fn from_bits(bits: u8) -> Option<ObjKind> {
        Some(match bits {
            1 => ObjKind::Commit,
            2 => ObjKind::Tree,
            3 => ObjKind::Blob,
            4 => ObjKind::Tag,
            6 => ObjKind::OfsDelta,
            7 => ObjKind::RefDelta,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            ObjKind::Commit => "commit",
            ObjKind::Tree => "tree",
            ObjKind::Blob => "blob",
            ObjKind::Tag => "tag",
            ObjKind::OfsDelta => "ofs-delta",
            ObjKind::RefDelta => "ref-delta",
        }
    }
    pub fn is_delta(self) -> bool {
        matches!(self, ObjKind::OfsDelta | ObjKind::RefDelta)
    }
    pub fn content_type_name(self) -> Option<&'static str> {
        match self {
            ObjKind::Commit => Some("commit"),
            ObjKind::Tree => Some("tree"),
            ObjKind::Blob => Some("blob"),
            ObjKind::Tag => Some("tag"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub kind: ObjKind,
    pub header_size: u64,
    pub inflated_size: u64,
    pub data: Vec<u8>,
    pub compressed_len: usize,
    pub ofs_target: Option<u64>,
    pub ref_target: Option<[u8; 20]>,
    pub crc: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct PackInfo {
    pub version: u32,
    pub entries: Vec<PackEntry>,
    pub trailing_sha: [u8; 20],
}

#[derive(Debug, Clone)]
pub struct IdxRecord {
    pub oid: [u8; 20],
    pub crc: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct IdxInfo {
    pub version: u32,
    pub records: Vec<IdxRecord>,
    pub pack_sha: [u8; 20],
    pub idx_sha: [u8; 20],
}

#[derive(Debug, Clone)]
pub struct LooseInfo {
    pub kind: ObjKind,
    pub content: Vec<u8>,
    pub inflated_size: u64,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum SourceKind {
    Pack = 0,
    Loose = 1,
}
