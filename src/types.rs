use serde::Serialize;

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl Kind {
    pub fn from_u8(t: u8) -> Option<Kind> {
        Some(match t {
            OBJ_COMMIT => Kind::Commit,
            OBJ_TREE => Kind::Tree,
            OBJ_BLOB => Kind::Blob,
            OBJ_TAG => Kind::Tag,
            _ => return None,
        })
    }
    pub fn name(&self) -> &'static str {
        match self {
            Kind::Commit => "commit",
            Kind::Tree => "tree",
            Kind::Blob => "blob",
            Kind::Tag => "tag",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObjStatus {
    Resolved,
    MissingBase,
    DeltaCycle,
    BadObject,
    PausedDepth,
    PausedBytes,
    PausedObject,
    Unindexed,
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub code: String,
    pub message: String,
    pub offset: Option<u64>,
}

impl ParseError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        ParseError {
            code: code.to_string(),
            message: message.into(),
            offset: None,
        }
    }
    pub fn at(mut self, off: u64) -> Self {
        self.offset = Some(off);
        self
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

#[derive(Debug, Clone)]
pub struct Budget {
    pub max_depth: u32,
    pub total_bytes: u64,
    pub max_object_ratio_num: u64,
    pub max_object_ratio_den: u64,
}

impl Default for Budget {
    fn default() -> Self {
        Budget {
            max_depth: 50,
            total_bytes: 64 * 1024 * 1024,
            max_object_ratio_num: 100,
            max_object_ratio_den: 1,
        }
    }
}
