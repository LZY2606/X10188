//! Low-level Git format primitives: object ids, zlib streams, pack/idx/loose
//! parsing and delta application. Everything here is implemented from scratch;
//! no system git binary is involved.

pub mod delta;
pub mod idx;
pub mod loose;
pub mod pack;
pub mod zlib;

use sha1::{Digest, Sha1};

/// 20-byte SHA-1 object id.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(pub [u8; 20]);

impl Oid {
    pub fn zero() -> Self {
        Oid([0u8; 20])
    }

    pub fn from_hex(s: &str) -> Option<Self> {
        let b = s.as_bytes();
        if b.len() != 40 {
            return None;
        }
        let mut out = [0u8; 20];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = hexval(b[i * 2])?;
            let lo = hexval(b[i * 2 + 1])?;
            *slot = (hi << 4) | lo;
        }
        Some(Oid(out))
    }

    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 20]
    }
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
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

/// Git pack object types (the on-disk 3-bit values).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl ObjType {
    pub fn from_u8(v: u8) -> Option<ObjType> {
        Some(match v {
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

    pub fn base_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            ObjType::OfsDelta | ObjType::RefDelta => None,
        }
    }
}

/// Read a Git little-endian-base-128 size varint, returning (value, bytes used).
pub fn read_size_varint(buf: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut p = pos;
    let mut shift = 0u32;
    let mut value: u64 = 0;
    loop {
        if p >= buf.len() {
            return Err("size varint runs past end of data".into());
        }
        let byte = buf[p];
        p += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("size varint too long".into());
        }
    }
    Ok((value, p - pos))
}

/// Read the n-byte ofs-delta "negative offset" encoding.
pub fn read_ofs_varint(buf: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut p = pos;
    if p >= buf.len() {
        return Err("ofs varint runs past end of data".into());
    }
    let mut byte = buf[p];
    p += 1;
    let mut dist: u64 = u64::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        if p >= buf.len() {
            return Err("ofs varint runs past end of data".into());
        }
        byte = buf[p];
        p += 1;
        dist = dist.wrapping_add(1);
        dist = (dist << 7) | u64::from(byte & 0x7f);
    }
    Ok((dist, p - pos))
}

/// Compute the Git object id for `content` claimed to be `kind`.
pub fn git_object_id(kind: ObjType, content: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(kind.base_name().expect("full object kind").as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    Oid(h.finalize().into())
}

/// Split a serialized git object `"<kind> <len>\\0<content>"`.
pub fn parse_loose_frame(frame: &[u8]) -> Result<(ObjType, &[u8]), String> {
    let nul = frame
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| "loose object missing NUL frame separator".to_string())?;
    let head = std::str::from_utf8(&frame[..nul]).map_err(|e| e.to_string())?;
    let (name, lenstr) = head
        .split_once(' ')
        .ok_or_else(|| "loose object header missing space".to_string())?;
    let kind = match name {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        other => return Err(format!("unknown loose object type {other}")),
    };
    let declared: usize = lenstr
        .parse()
        .map_err(|_| "loose object length not numeric".to_string())?;
    let body = &frame[nul + 1..];
    if body.len() != declared {
        return Err(format!(
            "loose object length mismatch: header says {declared}, body is {}",
            body.len()
        ));
    }
    Ok((kind, body))
}

/// Render `content` as text for previews, replacing control bytes.
pub fn preview(content: &[u8], max: usize) -> String {
    let mut out = String::new();
    for &b in content.iter().take(max) {
        if b == b'\n' || b == b'\t' || (0x20..=0x7e).contains(&b) {
            out.push(b as char);
        } else if b >= 0x80 {
            // Try UTF-8-ish: keep raw byte as replacement unless it decodes.
            out.push('\u{fffd}');
        } else {
            out.push('\\');
            out.push(match b {
                0 => '0',
                0x08 => 'b',
                0x0c => 'f',
                b'\r' => 'r',
                _ => 'x',
            });
        }
    }
    if content.len() > max {
        out.push('…');
    }
    out
}
