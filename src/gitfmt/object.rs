use super::oid::Oid;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjectKind {
    pub fn name(&self) -> &'static str {
        match self {
            ObjectKind::Commit => "commit",
            ObjectKind::Tree => "tree",
            ObjectKind::Blob => "blob",
            ObjectKind::Tag => "tag",
        }
    }
    pub fn from_type_id(t: u8) -> Option<Self> {
        match t {
            super::OBJ_COMMIT => Some(ObjectKind::Commit),
            super::OBJ_TREE => Some(ObjectKind::Tree),
            super::OBJ_BLOB => Some(ObjectKind::Blob),
            super::OBJ_TAG => Some(ObjectKind::Tag),
            _ => None,
        }
    }
}

/// Compute the git object id for raw payload: SHA1("<name> <len>\0<payload>").
pub fn git_object_id(kind: ObjectKind, payload: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(kind.name().as_bytes());
    h.update(b" ");
    h.update(payload.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(payload);
    let r = h.finalize();
    let mut o = [0u8; 20];
    o.copy_from_slice(&r);
    Oid(o)
}

pub fn wrap_object(kind: ObjectKind, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(payload.len() + 16);
    v.extend_from_slice(kind.name().as_bytes());
    v.push(b' ');
    v.extend_from_slice(payload.len().to_string().as_bytes());
    v.push(0);
    v.extend_from_slice(payload);
    v
}

/// Split a loose object's inflated form into (kind, payload).
pub fn split_loose(data: &[u8]) -> Result<(ObjectKind, Vec<u8>), String> {
    let sp = data
        .iter()
        .position(|&b| b == b' ')
        .ok_or_else(|| "loose object missing type".to_string())?;
    let nul = data[sp..]
        .iter()
        .position(|&b| b == 0)
        .map(|x| x + sp)
        .ok_or_else(|| "loose object missing NUL".to_string())?;
    let kind = match &data[..sp] {
        b"commit" => ObjectKind::Commit,
        b"tree" => ObjectKind::Tree,
        b"blob" => ObjectKind::Blob,
        b"tag" => ObjectKind::Tag,
        other => {
            return Err(format!(
                "loose object unknown type: {}",
                String::from_utf8_lossy(other)
            ))
        }
    };
    let declared_len: usize = std::str::from_utf8(&data[sp + 1..nul])
        .map_err(|_| "loose object length not ascii".to_string())?
        .parse()
        .map_err(|_| "loose object length not numeric".to_string())?;
    let payload = &data[nul + 1..];
    if declared_len != payload.len() {
        return Err(format!(
            "loose size spoof: header {}, actual {}",
            declared_len,
            payload.len()
        ));
    }
    Ok((kind, payload.to_vec()))
}

#[derive(Debug, Clone)]
pub struct TreeEntry {
    pub mode: String,
    pub name: String,
    pub oid: Oid,
    pub is_dir: bool,
}

pub fn parse_tree_entries(payload: &[u8]) -> Result<Vec<TreeEntry>, String> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < payload.len() {
        let sp = payload[p..]
            .iter()
            .position(|&b| b == b' ')
            .map(|x| x + p)
            .ok_or_else(|| "tree entry missing space".to_string())?;
        let nul = payload[sp + 1..]
            .iter()
            .position(|&b| b == 0)
            .map(|x| x + sp + 1)
            .ok_or_else(|| "tree entry missing NUL".to_string())?;
        let mode = std::str::from_utf8(&payload[p..sp])
            .map_err(|_| "tree mode not utf8".to_string())?
            .to_string();
        let name = std::str::from_utf8(&payload[sp + 1..nul])
            .map_err(|_| "tree name not utf8".to_string())?
            .to_string();
        if nul + 1 + 20 > payload.len() {
            return Err("tree entry oid truncated".into());
        }
        let mut o = [0u8; 20];
        o.copy_from_slice(&payload[nul + 1..nul + 21]);
        p = nul + 21;
        let is_dir = mode == "40000";
        out.push(TreeEntry { mode, name, oid: Oid(o), is_dir });
    }
    Ok(out)
}
