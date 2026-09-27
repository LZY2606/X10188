use serde::Serialize;

pub type Oid = [u8; 20];

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub enum GitType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl GitType {
    pub fn from_code(code: u8) -> Option<GitType> {
        Some(match code {
            1 => GitType::Commit,
            2 => GitType::Tree,
            3 => GitType::Blob,
            4 => GitType::Tag,
            6 => GitType::OfsDelta,
            7 => GitType::RefDelta,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
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
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize)]
pub enum Status {
    Ok,
    Blocked,
    Paused,
    Cycle,
    Corrupt,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Blocked => "blocked",
            Status::Paused => "paused",
            Status::Cycle => "cycle",
            Status::Corrupt => "corrupt",
        }
    }
    pub fn parse(s: &str) -> Status {
        match s {
            "ok" => Status::Ok,
            "blocked" => Status::Blocked,
            "paused" => Status::Paused,
            "cycle" => Status::Cycle,
            "corrupt" => Status::Corrupt,
            _ => Status::Corrupt,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub code: String,
    pub message: String,
}
