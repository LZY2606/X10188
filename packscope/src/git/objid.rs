//! Git object id (SHA-1 over `<type> <len>\0<body>`).

use sha1::{Digest, Sha1};

pub const OID_LEN: usize = 20;

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub struct Oid(pub [u8; OID_LEN]);

impl Oid {
    pub fn zero() -> Oid {
        Oid([0u8; OID_LEN])
    }

    pub fn from_bytes(b: &[u8]) -> Option<Oid> {
        if b.len() != OID_LEN {
            return None;
        }
        let mut o = [0u8; OID_LEN];
        o.copy_from_slice(b);
        Some(Oid(o))
    }

    pub fn from_hex(s: &str) -> Option<Oid> {
        let b = s.as_bytes();
        if b.len() != OID_LEN * 2 {
            return None;
        }
        let mut o = [0u8; OID_LEN];
        for i in 0..OID_LEN {
            let hi = (b[2 * i] as char).to_digit(16)? as u8;
            let lo = (b[2 * i + 1] as char).to_digit(16)? as u8;
            o[i] = (hi << 4) | lo;
        }
        Some(Oid(o))
    }

    pub fn hex(&self) -> String {
        let mut s = String::with_capacity(OID_LEN * 2);
        for b in &self.0 {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    pub fn short(&self) -> String {
        self.hex()[..8].to_string()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl std::fmt::Display for Oid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hex())
    }
}

impl Ord for Oid {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}
impl PartialOrd for Oid {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Object kinds used by git packs.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub enum ObjKind {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    /// Synthetic kind used for index entries whose pack is unavailable.
    IdxRef = 5,
}

impl ObjKind {
    pub fn from_code(c: u8) -> Option<ObjKind> {
        Some(match c {
            1 => ObjKind::Commit,
            2 => ObjKind::Tree,
            3 => ObjKind::Blob,
            4 => ObjKind::Tag,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            ObjKind::Commit => "commit",
            ObjKind::Tree => "tree",
            ObjKind::Blob => "blob",
            ObjKind::Tag => "tag",
            ObjKind::IdxRef => "idx-ref",
        }
    }

    pub fn parse(s: &str) -> Option<ObjKind> {
        Some(match s {
            "commit" => ObjKind::Commit,
            "tree" => ObjKind::Tree,
            "blob" => ObjKind::Blob,
            "tag" => ObjKind::Tag,
            "idx-ref" => ObjKind::IdxRef,
            _ => return None,
        })
    }
}

/// Compute the git object id for a fully inflated object payload.
pub fn git_oid(kind: ObjKind, body: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(kind.name().as_bytes());
    h.update(b" ");
    h.update(body.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(body);
    Oid(h.finalize().into())
}
