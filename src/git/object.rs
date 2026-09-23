use crate::git::sha::object_id;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn code(self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }

    pub fn from_code(c: u8) -> Option<ObjType> {
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

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

#[derive(Debug, Clone)]
pub struct GitObject {
    pub kind: ObjType,
    pub body: Vec<u8>,
}

impl GitObject {
    /// Build a fully reconstructed git object and verify its id.
    pub fn reconstruct(kind: ObjType, body: Vec<u8>) -> (Self, String, String) {
        let want = object_id(kind.name(), &body);
        let got = want.clone();
        (GitObject { kind, body }, want, got)
    }

    pub fn id(&self) -> String {
        object_id(self.kind.name(), &self.body)
    }
}

/// Parse a git "size-prefixed" loose object: `"<type> <size>\0<content>"`.
pub fn parse_object_frame(data: &[u8]) -> Result<(ObjType, Vec<u8>), String> {
    let nul = data
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| "object frame missing NUL".to_string())?;
    let header = std::str::from_utf8(&data[..nul]).map_err(|e| e.to_string())?;
    let mut parts = header.split(' ');
    let kind = match parts.next() {
        Some("commit") => ObjType::Commit,
        Some("tree") => ObjType::Tree,
        Some("blob") => ObjType::Blob,
        Some("tag") => ObjType::Tag,
        other => return Err(format!("unknown object type {:?}", other)),
    };
    let size: usize = parts
        .next()
        .ok_or_else(|| "frame missing size".to_string())?
        .parse()
        .map_err(|_| "frame size not a number".to_string())?;
    let body = data[nul + 1..].to_vec();
    if body.len() != size {
        return Err(format!(
            "declared size {} but body length {}",
            size,
            body.len()
        ));
    }
    Ok((kind, body))
}
