pub type Oid20 = [u8; 20];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_type_id(id: u8) -> Option<ObjType> {
        match id {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
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
    pub fn parse(s: &str) -> Option<ObjType> {
        match s {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            "ofs-delta" => Some(ObjType::OfsDelta),
            "ref-delta" => Some(ObjType::RefDelta),
            _ => None,
        }
    }
    pub fn is_base(self) -> bool {
        matches!(self, ObjType::Commit | ObjType::Tree | ObjType::Blob | ObjType::Tag)
    }
    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

pub fn hex_oid(o: &Oid20) -> String {
    let mut s = String::with_capacity(40);
    for b in o {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn parse_oid(s: &str) -> Option<Oid20> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    let bs = s.as_bytes();
    for i in 0..20 {
        let h = hex_val(bs[i * 2])?;
        let l = hex_val(bs[i * 2 + 1])?;
        out[i] = (h << 4) | l;
    }
    Some(out)
}

pub fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

pub fn is_hex_oid_name(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| hex_val(b).is_some())
}

/// Git loose-object / canonical object framing: `"<type> <len>\0<content>"`.
pub fn frame_object(typ: ObjType, content: &[u8]) -> Vec<u8> {
    let mut v = format!("{} {}\0", typ.name(), content.len()).into_bytes();
    v.extend_from_slice(content);
    v
}

pub fn git_object_id(typ: ObjType, content: &[u8]) -> Oid20 {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(&frame_object(typ, content));
    h.finalize().into()
}
