//! Low level Git object / pack / index primitives implemented from scratch.

pub mod base;
pub mod delta;
pub mod pack;
pub mod idx;
pub mod loose;

/// Git object types, identified by the numeric code used in pack entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    /// OFS_DELTA (offset delta, base addressed by negative pack offset).
    OfsDelta = 6,
    /// REF_DELTA (base addressed by 20 byte object id).
    RefDelta = 7,
}

impl GitType {
    pub fn from_pack(code: u8) -> Option<GitType> {
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

    pub fn is_delta(self) -> bool {
        matches!(self, GitType::OfsDelta | GitType::RefDelta)
    }

    pub fn base_type_code(self) -> Option<u8> {
        match self {
            GitType::Commit => Some(1),
            GitType::Tree => Some(2),
            GitType::Blob => Some(3),
            GitType::Tag => Some(4),
            _ => None,
        }
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

    pub fn from_name(name: &str) -> Option<GitType> {
        Some(match name {
            "commit" => GitType::Commit,
            "tree" => GitType::Tree,
            "blob" => GitType::Blob,
            "tag" => GitType::Tag,
            _ => return None,
        })
    }
}

/// Compute the Git object id (sha1 of `"<type> <size>\0<data>"`).
pub fn git_object_id(type_name: &str, data: &[u8]) -> [u8; 20] {
    use sha1_smol::Sha1;
    let mut hasher = Sha1::new();
    hasher.update(type_name.as_bytes());
    hasher.update(b" ");
    hasher.update(data.len().to_string().as_bytes());
    hasher.update(&[0]);
    hasher.update(data);
    hasher.digest().bytes()
}

/// Encode the loose-object payload `"<type> <size>\0<data>"`.
pub fn loose_payload(type_name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 16);
    out.extend_from_slice(type_name.as_bytes());
    out.push(b' ');
    out.extend_from_slice(data.len().to_string().as_bytes());
    out.push(0);
    out.extend_from_slice(data);
    out
}

/// Read the little-endian-base-128 size/type header of a pack entry.
/// Returns (type_code, size, bytes_consumed).
pub fn read_pack_entry_header(data: &[u8], pos: usize) -> Result<(u8, u64, usize), String> {
    let mut p = pos;
    if p >= data.len() {
        return Err("unexpected end of pack entry header".into());
    }
    let first = data[p];
    p += 1;
    let type_code = (first >> 4) & 0b111;
    let mut size: u64 = (first & 0x0f) as u64;
    let mut shift: u32 = 4;
    let mut c = first;
    while c & 0x80 != 0 {
        if p >= data.len() {
            return Err("truncated pack entry header (continuation)".into());
        }
        c = data[p];
        p += 1;
        size |= ((c & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok((type_code, size, p - pos))
}

/// Read the OFS_DELTA negative-offset variable length encoding.
/// Returns (offset_distance, bytes_consumed).
pub fn read_ofs_distance(data: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut p = pos;
    if p >= data.len() {
        return Err("truncated ofs-delta header".into());
    }
    let mut c = data[p];
    p += 1;
    let mut ofs: u64 = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        if p >= data.len() {
            return Err("truncated ofs-delta offset".into());
        }
        ofs += 1;
        c = data[p];
        p += 1;
        ofs = (ofs << 7) | ((c & 0x7f) as u64);
    }
    Ok((ofs, p - pos))
}

/// Decompress one zlib stream starting at `start`, stopping at the stream
/// boundary (rather than reading to the end of the buffer).
/// Returns the decompressed bytes and the number of compressed bytes consumed.
pub fn inflate_one(data: &[u8], start: usize) -> Result<(Vec<u8>, usize), String> {
    use flate2::Decompress;
    use flate2::FlushDecompress;
    let mut decomp = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut in_pos = start;
    let mut buf = [0u8; 4096];
    loop {
        if in_pos >= data.len() {
            return Err("truncated zlib stream (no more input)".into());
        }
        let before_in = decomp.total_in();
        let before_out = decomp.total_out();
        let res = decomp
            .inflate(&data[in_pos..], &mut buf, FlushDecompress::None)
            .map_err(|e| format!("zlib error: {e}"))?;
        let consumed = (decomp.total_in() - before_in) as usize;
        let produced = (decomp.total_out() - before_out) as usize;
        in_pos += consumed;
        out.extend_from_slice(&buf[..produced]);
        if res == flate2::Status::StreamEnd {
            break;
        }
        if res == flate2::Status::Ok && consumed == 0 && produced == 0 {
            return Err("zlib stalled without progress".into());
        }
    }
    let used = (decomp.total_in()) as usize;
    Ok((out, used))
}
