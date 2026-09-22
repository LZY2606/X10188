// Low level Git object format helpers (implemented from scratch, no git binary).

use sha1::{Digest, Sha1};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum GitType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl GitType {
    pub fn name(self) -> &'static str {
        match self {
            GitType::Commit => "commit",
            GitType::Tree => "tree",
            GitType::Blob => "blob",
            GitType::Tag => "tag",
        }
    }

    pub fn from_code(code: u8) -> Option<GitType> {
        Some(match code {
            1 => GitType::Commit,
            2 => GitType::Tree,
            3 => GitType::Blob,
            4 => GitType::Tag,
            _ => return None,
        })
    }

    pub fn from_name(name: &[u8]) -> Option<GitType> {
        Some(match name {
            b"commit" => GitType::Commit,
            b"tree" => GitType::Tree,
            b"blob" => GitType::Blob,
            b"tag" => GitType::Tag,
            _ => return None,
        })
    }
}

/// Compute the Git object id (SHA1 over "<type> <size>\0<content>").
pub fn git_object_id(kind: GitType, data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(kind.name().as_bytes());
    h.update(b" ");
    h.update(data.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

/// Pack entry type as recorded in a pack entry header.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum EntryType {
    Base(GitType),
    OfsDelta,
    RefDelta,
}

impl EntryType {
    pub fn label(self) -> &'static str {
        match self {
            EntryType::Base(t) => t.name(),
            EntryType::OfsDelta => "ofs-delta",
            EntryType::RefDelta => "ref-delta",
        }
    }

    fn from_pack_code(code: u8) -> Option<EntryType> {
        Some(match code {
            1..=4 => EntryType::Base(GitType::from_code(code).unwrap()),
            6 => EntryType::OfsDelta,
            7 => EntryType::RefDelta,
            _ => return None,
        })
    }
}

#[derive(Debug)]
pub enum ParseError {
    Truncated(String),
    BadEncoding(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Truncated(s) | ParseError::BadEncoding(s) => write!(f, "{s}"),
        }
    }
}

/// Read the pack entry type/size variable header. Returns (type, size, header_end).
pub fn read_entry_head(buf: &[u8], pos: usize) -> Result<(EntryType, u64, usize), ParseError> {
    let mut p = pos;
    let first = *buf.get(p).ok_or_else(|| {
        ParseError::Truncated("entry header byte missing".into())
    })?;
    p += 1;
    let code = (first >> 4) & 0x7;
    let etype = EntryType::from_pack_code(code)
        .ok_or_else(|| ParseError::BadEncoding(format!("unknown pack object type {code}")))?;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4;
    let mut b = first;
    while b & 0x80 != 0 {
        b = *buf
            .get(p)
            .ok_or_else(|| ParseError::Truncated("size varint truncated".into()))?;
        p += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok((etype, size, p))
}

/// Read an ofs-delta negative relative offset. Returns (distance, header_end).
pub fn read_ofs_distance(buf: &[u8], pos: usize) -> Result<(u64, usize), ParseError> {
    let mut p = pos;
    let mut c = *buf
        .get(p)
        .ok_or_else(|| ParseError::Truncated("ofs byte missing".into()))?;
    p += 1;
    let mut dist = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        dist += 1;
        dist <<= 7;
        c = *buf
            .get(p)
            .ok_or_else(|| ParseError::Truncated("ofs varint truncated".into()))?;
        p += 1;
        dist += (c & 0x7f) as u64;
    }
    Ok((dist, p))
}

/// Read an unsigned little-endian-base-128 varint as used inside delta payloads.
pub fn read_delta_varint(buf: &[u8], pos: usize) -> Result<(u64, usize), ParseError> {
    let mut p = pos;
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf
            .get(p)
            .ok_or_else(|| ParseError::Truncated("delta varint truncated".into()))?;
        p += 1;
        val |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(ParseError::BadEncoding("delta varint too long".into()));
        }
    }
    Ok((val, p))
}

/// Parse a loose-object header "<type> <size>\0" from inflated bytes.
pub fn parse_loose_header(buf: &[u8]) -> Result<(GitType, usize, usize), ParseError> {
    let nul = buf
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| ParseError::BadEncoding("loose header NUL missing".into()))?;
    let header = &buf[..nul];
    let sp = header
        .iter()
        .position(|b| *b == b' ')
        .ok_or_else(|| ParseError::BadEncoding("loose header space missing".into()))?;
    let kind = GitType::from_name(&header[..sp])
        .ok_or_else(|| ParseError::BadEncoding("unknown loose type".into()))?;
    let size: usize = std::str::from_utf8(&header[sp + 1..])
        .map_err(|_| ParseError::BadEncoding("loose size not ascii".into()))?
        .parse()
        .map_err(|_| ParseError::BadEncoding("loose size not numeric".into()))?;
    Ok((kind, size, nul + 1))
}
