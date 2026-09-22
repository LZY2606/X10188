use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        Some(match code {
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
    pub fn is_base(self) -> bool {
        matches!(self, ObjType::Commit | ObjType::Tree | ObjType::Blob | ObjType::Tag)
    }
}

/// Variable-length size/type header used in pack entries.
/// Returns (type_code, size, bytes_consumed).
pub fn read_entry_header(buf: &[u8]) -> Option<(u8, u64, usize)> {
    if buf.is_empty() {
        return None;
    }
    let first = buf[0];
    let kind = (first >> 4) & 0b111;
    let mut size: u64 = (first & 0x0f) as u64;
    let mut shift: u32 = 4;
    let mut pos = 1;
    let mut cur = first;
    while cur & 0x80 != 0 {
        if pos >= buf.len() {
            return None;
        }
        cur = buf[pos];
        size |= ((cur & 0x7f) as u64) << shift;
        shift += 7;
        pos += 1;
    }
    Some((kind, size, pos))
}

/// LEB128 style unsigned varint used in delta instruction streams.
/// Returns (value, bytes_consumed).
pub fn read_delta_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= buf.len() {
            return None;
        }
        let b = buf[*pos];
        *pos += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    Some(result)
}

pub fn to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    hex::decode(s).ok()
}

/// Compute a Git loose-object-style SHA-1 over `header <type> <len>\\0<body>`.
pub fn git_object_id(kind: ObjType, body: &[u8]) -> [u8; 20] {
    let header = format!("{} {}\0", kind.name(), body.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(body);
    let out = hasher.finalize();
    let mut id = [0u8; 20];
    id.copy_from_slice(&out);
    id
}

/// SHA1 over raw bytes (pack / idx trailer checksums).
pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    let mut id = [0u8; 20];
    id.copy_from_slice(&hasher.finalize());
    id
}

/// Best-effort content summary for preview.
pub fn summarize(data: &[u8]) -> String {
    let preview_len = data.len().min(4096);
    let slice = &data[..preview_len];
    let printable = slice
        .iter()
        .filter(|b| (**b == b'\n' || **b == b'\t' || (0x20..=0x7e).contains(*b)))
        .count();
    if slice.is_empty() {
        return String::from("(empty)");
    }
    let ratio = printable as f64 / slice.len() as f64;
    if ratio > 0.85 {
        String::from_utf8_lossy(slice).replace('\0', "\\0")
    } else {
        let mut s = String::from("binary: ");
        for b in slice.iter().take(64) {
            s.push_str(&format!("{b:02x}"));
        }
        if data.len() > 64 {
            s.push('…');
        }
        s
    }
}
