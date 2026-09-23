//! Core domain types shared by the parser, engine and web layer.

/// The four normal git object types plus the two delta flavours.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GitType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
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

    pub fn from_loose_name(name: &str) -> Option<GitType> {
        match name {
            "commit" => Some(GitType::Commit),
            "tree" => Some(GitType::Tree),
            "blob" => Some(GitType::Blob),
            "tag" => Some(GitType::Tag),
            _ => None,
        }
    }

    pub fn loose_name(self) -> Option<&'static str> {
        match self {
            GitType::Commit => Some("commit"),
            GitType::Tree => Some("tree"),
            GitType::Blob => Some("blob"),
            GitType::Tag => Some("tag"),
            GitType::OfsDelta | GitType::RefDelta => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
            GitType::OfsDelta => "ofs-delta",
            GitType::RefDelta => "ref-delta",
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, GitType::OfsDelta | GitType::RefDelta)
    }

    pub fn is_base(self) -> bool {
        !self.is_delta()
    }
}

/// Kind of imported source file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceKind {
    Pack,
    Idx,
    Loose,
}

impl SourceKind {
    pub fn label(self) -> &'static str {
        match self {
            SourceKind::Pack => "pack",
            SourceKind::Idx => "idx",
            SourceKind::Loose => "loose",
        }
    }
}
