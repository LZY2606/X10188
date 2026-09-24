//! Core git object model: type tags, content hashing, varint helpers.

use sha1::{Digest, Sha1};

/// Git object types known inside packs / loose storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    /// Type 6 only valid inside packs (OFS_DELTA).
    OfsDelta,
    /// Type 7 only valid inside packs (REF_DELTA).
    RefDelta,
}

impl ObjType {
    pub fn from_pack_tag(tag: u8) -> Option<ObjType> {
        match tag {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn from_loose(name: &str) -> Option<ObjType> {
        match name {
            "commit" => Some(ObjType::Commit),
            "tree" => Some(ObjType::Tree),
            "blob" => Some(ObjType::Blob),
            "tag" => Some(ObjType::Tag),
            _ => None,
        }
    }

    pub fn loose_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            ObjType::OfsDelta | ObjType::RefDelta => None,
        }
    }

    /// Pack on-disk type tag (1..=7).
    pub fn pack_tag(self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

/// Read an unsigned little-endian-base-128 varint as used in pack object
/// headers and delta instruction streams. Returns `(value, bytes_consumed)`.
pub fn read_size_encoding(data: &[u8]) -> Option<(u64, usize)> {
    let mut shift: u32 = 0;
    let mut result: u64 = 0;
    for (i, &b) in data.iter().enumerate() {
        if shift >= 64 {
            return None;
        }
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
    }
    None
}

/// Read the pack entry header: first byte holds the type tag in bits 6..4 and
/// the low 4 bits of the size; continuation bytes follow.
/// Returns `(type, inflated_size, header_len)`.
pub fn read_pack_obj_header(data: &[u8]) -> Option<(ObjType, u64, usize)> {
    let first = *data.first()?;
    let tag = (first >> 4) & 0b111;
    let obj_type = ObjType::from_pack_tag(tag)?;
    let mut size = (first & 0x0f) as u64;
    let mut consumed = 1;
    if first & 0x80 != 0 {
        let (rest, n) = read_size_encoding(&data[1..])?;
        size |= rest << 4;
        consumed += n;
    }
    Some((obj_type, size, consumed))
}

/// Read an OFS_DELTA negative-offset varint directly after the object header.
/// Git's special encoding (MSB-first, first byte's lower bits + continuation
/// with implicit high bit). Returns `(distance, bytes_consumed)`.
pub fn read_ofs_distance(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let mut value = (first & 0x7f) as u64;
    let mut consumed = 1;
    let mut cur = first;
    while cur & 0x80 != 0 {
        cur = *data.get(consumed)?;
        consumed += 1;
        value = value.wrapping_add(1);
        value = (value << 7) | (cur & 0x7f) as u64;
    }
    Some((value, consumed))
}

/// Compute the git object id (`sha1("<type> <len>\0<body>")`) and return hex.
pub fn git_object_id(obj_type: ObjType, body: &[u8]) -> String {
    let name = obj_type.loose_name().expect("delta has no object id");
    let mut hasher = Sha1::new();
    hasher.update(name.as_bytes());
    hasher.update(b" ");
    hasher.update(body.len().to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(body);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_blob_id() {
        assert_eq!(
            git_object_id(ObjType::Blob, b""),
            "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"
        );
    }

    #[test]
    fn varint_roundtrip_and_ofs() {
        assert_eq!(read_size_encoding(&[0x00]), Some((0, 1)));
        assert_eq!(read_size_encoding(&[0x96, 0x01]), Some((150, 2)));
        // ofs encoding examples from git docs:
        assert_eq!(read_ofs_distance(&[0x05]), Some((5, 1)));
        assert_eq!(read_ofs_distance(&[0x80, 0x01]), Some((129, 2)));
    }
}
