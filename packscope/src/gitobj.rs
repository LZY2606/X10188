use crate::oid::Oid;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

/// Object type stored in a pack (the three delta kinds only occur in packs).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_pack_code(c: u8) -> Option<ObjType> {
        Some(match c {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            6 => ObjType::OfsDelta,
            7 => ObjType::RefDelta,
            _ => return None,
        })
    }
    pub fn is_delta(&self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
    pub fn base_kind(&self) -> Option<ObjType> {
        match self {
            ObjType::Commit | ObjType::Tree | ObjType::Blob | ObjType::Tag => Some(*self),
            _ => None,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }
    pub fn from_name(s: &str) -> Option<ObjType> {
        Some(match s {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            _ => return None,
        })
    }
}

/// Compute the Git object id: sha1("<type> <len>\0<content>").
pub fn hash_object(kind: ObjType, content: &[u8]) -> Oid {
    let header = format!("{} {}\0", kind.name(), content.len());
    let mut h = Sha1::new();
    h.update(header.as_bytes());
    h.update(content);
    let mut out = [0u8; 20];
    out.copy_from_slice(&h.finalize());
    Oid(out)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeEntry {
    pub mode: String,
    pub name: String,
    pub oid: Oid,
}

/// Parse a tree object body. Returns None if malformed.
pub fn parse_tree(body: &[u8]) -> Option<Vec<TreeEntry>> {
    let mut entries = Vec::new();
    let mut pos = 0;
    while pos < body.len() {
        let sp = body[pos..].iter().position(|&b| b == b' ')?;
        let mode = std::str::from_utf8(&body[pos..pos + sp]).ok()?;
        pos += sp + 1;
        let nul = body[pos..].iter().position(|&b| b == 0)?;
        let name = std::str::from_utf8(&body[pos..pos + nul])
            .ok()?
            .to_string();
        pos += nul + 1;
        if pos + 20 > body.len() {
            return None;
        }
        let oid = Oid::from_bytes(&body[pos..pos + 20])?;
        pos += 20;
        entries.push(TreeEntry {
            mode: mode.to_string(),
            name,
            oid,
        });
    }
    Some(entries)
}

/// A short, lossy text preview of object content.
pub fn preview(kind: ObjType, body: &[u8], limit: usize) -> String {
    match kind {
        ObjType::Tree => {
            if let Some(es) = parse_tree(body) {
                let mut s = String::new();
                for e in es {
                    s.push_str(&format!("{} {} {}\n", e.mode, e.oid.short(), e.name));
                }
                truncate(s, limit)
            } else {
                hex_preview(body, limit)
            }
        }
        _ => {
            let text = String::from_utf8_lossy(body);
            truncate(text.into_owned(), limit)
        }
    }
}

fn truncate(mut s: String, limit: usize) -> String {
    if s.len() > limit {
        while !s.is_char_boundary(limit.min(s.len())) {}
        s.truncate(limit);
        s.push_str("\n…(truncated)");
    }
    s
}

fn hex_preview(body: &[u8], limit: usize) -> String {
    let n = (limit / 2).min(body.len());
    hex::encode(&body[..n])
}
