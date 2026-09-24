use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjectType {
    pub fn from_pack(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Commit),
            2 => Some(Self::Tree),
            3 => Some(Self::Blob),
            4 => Some(Self::Tag),
            _ => None,
        }
    }

    pub fn from_name(value: &[u8]) -> Option<Self> {
        match value {
            b"commit" => Some(Self::Commit),
            b"tree" => Some(Self::Tree),
            b"blob" => Some(Self::Blob),
            b"tag" => Some(Self::Tag),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Pack,
    Index,
    Loose,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Base,
    OfsDelta,
    RefDelta,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeltaOp {
    Copy,
    Insert,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub code: String,
    pub message: String,
    pub offset: Option<u64>,
}

impl Evidence {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            offset: None,
        }
    }

    pub fn at(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaInstruction {
    pub op: DeltaOp,
    pub range_start: u64,
    pub range_len: u64,
    pub base_offset: Option<u64>,
    pub base_len: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaRef {
    pub kind: NodeKind,
    pub negative_offset: Option<u64>,
    pub target_offset: Option<u64>,
    pub target_oid: Option<String>,
    pub declared_base_size: u64,
    pub declared_result_size: u64,
    pub instruction_start: u64,
    pub instructions: Vec<DeltaInstruction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedNode {
    pub id: String,
    pub source_id: String,
    pub source_kind: SourceKind,
    pub original_name: String,
    pub offset: u64,
    pub end_offset: Option<u64>,
    pub header_len: u64,
    pub compressed_start: u64,
    pub compressed_end: Option<u64>,
    pub kind: NodeKind,
    pub object_type: Option<ObjectType>,
    pub claimed_size: u64,
    pub data: Vec<u8>,
    pub crc32: Option<u32>,
    pub expected_crc32: Option<u32>,
    pub adler_ok: Option<bool>,
    pub loose_oid: Option<String>,
    pub delta: Option<DeltaRef>,
    pub errors: Vec<Evidence>,
}

impl ParsedNode {
    pub fn is_parse_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexFanout {
    pub bucket: usize,
    pub cumulative: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub oid: String,
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedIndex {
    pub source_id: String,
    pub original_name: String,
    pub pack_checksum: String,
    pub index_checksum: String,
    pub entry_count: u32,
    pub fanout: Vec<IndexFanout>,
    pub entries: Vec<IndexEntry>,
    pub errors: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPack {
    pub source_id: String,
    pub original_name: String,
    pub pack_checksum: String,
    pub object_count: u32,
    pub version: u32,
    pub header_len: u64,
    pub nodes: Vec<ParsedNode>,
    pub errors: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParseImport {
    pub source_id: String,
    pub original_name: String,
    pub kind: SourceKind,
    pub sha256: String,
    pub len: u64,
    pub packs: Vec<ParsedPack>,
    pub indexes: Vec<ParsedIndex>,
    pub nodes: Vec<ParsedNode>,
    pub errors: Vec<Evidence>,
}
