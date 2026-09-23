use serde::Serialize;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub fn from_hex(s: &str) -> Option<Oid> {
        let s = s.trim();
        if s.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        hex::decode_to_slice(s, &mut out).ok()?;
        Some(Oid(out))
    }

    pub fn from_bytes(b: &[u8]) -> Option<Oid> {
        if b.len() != 20 {
            return None;
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(b);
        Some(Oid(out))
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn short(&self) -> String {
        self.hex()[..12].to_string()
    }
}

impl std::fmt::Debug for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Oid({})", self.hex())
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl Serialize for Oid {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.hex())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GitType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl GitType {
    pub fn from_pack_code(code: u8) -> Option<GitType> {
        match code {
            1 => Some(GitType::Commit),
            2 => Some(GitType::Tree),
            3 => Some(GitType::Blob),
            4 => Some(GitType::Tag),
            6 => Some(GitType::OfsDelta),
            7 => Some(GitType::RefDelta),
            _ => None,
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, GitType::OfsDelta | GitType::RefDelta)
    }

    pub fn header_name(self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
            GitType::OfsDelta => "ofs-delta",
            GitType::RefDelta => "ref-delta",
        }
    }

    pub fn from_loose_name(s: &str) -> Option<GitType> {
        match s {
            "commit" => Some(GitType::Commit),
            "tree" => Some(GitType::Tree),
            "blob" => Some(GitType::Blob),
            "tag" => Some(GitType::Tag),
            _ => None,
        }
    }
}

/// Where a candidate object lives inside an imported source file.
#[derive(Clone, Debug)]
pub enum Location {
    Pack {
        source_id: i64,
        pack_checksum: Oid,
        entry_offset: u64,
        data_offset: u64,
        compressed_end: Option<u64>,
        crc32: Option<u32>,
    },
    Loose {
        source_id: i64,
        rel_path: String,
        data_offset: u64,
    },
}

impl Location {
    pub fn source_id(&self) -> i64 {
        match self {
            Location::Pack { source_id, .. } => *source_id,
            Location::Loose { source_id, .. } => *source_id,
        }
    }

    pub fn primary_offset(&self) -> u64 {
        match self {
            Location::Pack { entry_offset, .. } => *entry_offset,
            Location::Loose { data_offset, .. } => *data_offset,
        }
    }
}

/// Result of parsing one source file (pack / idx / loose).
#[derive(Clone, Debug, Default, Serialize)]
pub struct SourceSummary {
    pub source_id: i64,
    pub filename: String,
    pub kind: String,
    pub size: u64,
    pub sha256: String,
    pub notes: Vec<String>,
    pub errors: Vec<Evidence>,
}

/// Human/machine readable piece of evidence attached to a failed parse.
#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
}

impl Evidence {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Evidence {
            code: code.to_string(),
            message: message.into(),
            offset: None,
            expected: None,
            actual: None,
        }
    }

    pub fn at(mut self, offset: u64) -> Self {
        self.offset = Some(offset);
        self
    }
}
