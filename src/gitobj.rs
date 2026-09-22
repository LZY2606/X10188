//! Git object types and SHA-1 object id recomputation.
//!
//! A loose/pack *base* object is stored as `<type> SP <len> NUL <payload>`;
//! the git object id is sha1 of that exact encoding.

use crate::oid::Oid;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitKind {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
    Unknown(u8),
}

impl GitKind {
    pub fn from_pack_bits(bits: u8) -> GitKind {
        match bits {
            1 => GitKind::Commit,
            2 => GitKind::Tree,
            3 => GitKind::Blob,
            4 => GitKind::Tag,
            6 => GitKind::OfsDelta,
            7 => GitKind::RefDelta,
            n => GitKind::Unknown(n),
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, GitKind::OfsDelta | GitKind::RefDelta)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            GitKind::Commit => "commit",
            GitKind::Tree => "tree",
            GitKind::Blob => "blob",
            GitKind::Tag => "tag",
            GitKind::OfsDelta => "ofs-delta",
            GitKind::RefDelta => "ref-delta",
            GitKind::Unknown(_) => "unknown",
        }
    }

    pub fn from_loose_name(s: &str) -> Option<GitKind> {
        Some(match s {
            "commit" => GitKind::Commit,
            "tree" => GitKind::Tree,
            "blob" => GitKind::Blob,
            "tag" => GitKind::Tag,
            _ => return None,
        })
    }
}

/// Recalculate the git object id for a fully materialized object.
pub fn hash_object(kind: GitKind, payload: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(kind.as_str().as_bytes());
    h.update(b" ");
    h.update(payload.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(payload);
    Oid(h.finalize().into())
}

/// Decode a loose object's `"<type> <len>\0<payload>"` envelope.
pub fn decode_loose_envelope(raw: &[u8]) -> Result<(GitKind, &[u8]), String> {
    let sp = raw
        .iter()
        .position(|&b| b == b' ')
        .ok_or_else(|| "loose object missing type separator".to_string())?;
    let nul = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "loose object missing NUL".to_string())?;
    if nul <= sp {
        return Err("malformed loose object header".into());
    }
    let kind = std::str::from_utf8(&raw[..sp])
        .map_err(|_| "loose type not utf8".to_string())
        .and_then(|s| GitKind::from_loose_name(s).ok_or_else(|| format!("unknown type {s}")))?;
    let len: usize = std::str::from_utf8(&raw[sp + 1..nul])
        .map_err(|_| "loose length not utf8".to_string())?
        .parse()
        .map_err(|_| "loose length not a number".to_string())?;
    let payload = &raw[nul + 1..];
    if payload.len() != len {
        return Err(format!(
            "loose object length mismatch: header says {len}, payload is {}",
            payload.len()
        ));
    }
    Ok((kind, payload))
}
