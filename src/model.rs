use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn code(&self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }

    /// Git type name for real (non-delta) objects.
    pub fn type_name(&self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            _ => None,
        }
    }

    pub fn is_delta(&self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }

    pub fn label(&self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeltaBase {
    Ofs { distance: u64 },
    Ref { oid: String },
}

/// One element of a resolved delta chain, in application order after reversal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChainElem {
    /// Non-delta pack object; chain starts here.
    Full { pobj: i64 },
    /// Delta pack object applied on top of the previous element.
    Delta { pobj: i64 },
    /// Pack object that already has an ok candidate; use its stored content.
    Resolved { pobj: i64 },
    /// External base identified by oid (from object store, e.g. loose object).
    External { oid: String },
}

/// Description of one blocking link, recorded for unresolved objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockingLink {
    pub pack_object_id: Option<i64>,
    pub source_id: Option<i64>,
    pub offset: Option<u64>,
    pub reason: String,
}
