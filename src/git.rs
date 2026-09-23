//! Low-level Git object encoding helpers (no system git involved).

use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GitType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl GitType {
    pub fn from_pack_code(code: u8) -> Option<GitType> {
        match code {
            1 => Some(GitType::Commit),
            2 => Some(GitType::Tree),
            3 => Some(GitType::Blob),
            4 => Some(GitType::Tag),
            6 => Some(GitType::OfsDelta),
            7 => Some(GitType::RefDelta),
            _ => None,
        }
    }

    pub fn is_base(self) -> bool {
        matches!(
            self,
            GitType::Commit | GitType::Tree | GitType::Blob | GitType::Tag
        )
    }

    pub fn is_delta(self) -> bool {
        matches!(self, GitType::OfsDelta | GitType::RefDelta)
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

    pub fn from_loose_name(s: &str) -> Option<GitType> {
        match s {
            "commit" => Some(GitType::Commit),
            "tree" => Some(GitType::Tree),
            "blob" => Some(GitType::Blob),
            "tag" => Some(GitType::Tag),
            _ => None,
        }
    }

    pub fn code(self) -> Option<u8> {
        match self {
            GitType::Commit => Some(1),
            GitType::Tree => Some(2),
            GitType::Blob => Some(3),
            GitType::Tag => Some(4),
            GitType::OfsDelta => Some(6),
            GitType::RefDelta => Some(7),
        }
    }
}

/// Compute the Git object id (sha1 of `"<type> <len>\0<body>"`).
pub fn object_id(ty: GitType, body: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(ty.name().as_bytes());
    hasher.update(b" ");
    hasher.update(body.len().to_string().as_bytes());
    hasher.update([0u8]);
    hasher.update(body);
    hasher.finalize().into()
}

/// Pack entry header: (type_code, uncompressed size, header length).
pub fn parse_pack_entry_header(buf: &[u8]) -> Option<(u8, u64, usize)> {
    let first = *buf.first()?;
    let ty = (first >> 4) & 0x7;
    let mut size: u64 = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut pos = 1usize;
    let mut byte = first;
    while byte & 0x80 != 0 {
        byte = *buf.get(pos)?;
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        pos += 1;
    }
    Some((ty, size, pos))
}

/// Encode a pack entry header (used by the test pack builder).
pub fn encode_pack_entry_header(ty: u8, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut first = (ty & 0x7) << 4;
    first |= (size & 0x0f) as u8;
    let mut rest = size >> 4;
    if rest > 0 {
        first |= 0x80;
    }
    out.push(first);
    while rest > 0 {
        let mut b = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest > 0 {
            b |= 0x80;
        }
        out.push(b);
    }
    out
}

/// Encode the non-negative varint used at the start of delta instructions
/// (source/target sizes).
pub fn encode_delta_size(mut n: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        out.push(b);
        if n == 0 {
            break;
        }
    }
    out
}

/// Parse a non-negative varint from delta instructions.
/// Returns (value, bytes_consumed).
pub fn parse_delta_size(buf: &[u8]) -> Option<(u64, usize)> {
    let mut size: u64 = 0;
    let mut shift = 0u32;
    let mut pos = 0usize;
    loop {
        let b = *buf.get(pos)?;
        size |= ((b & 0x7f) as u64) << shift;
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    Some((size, pos))
}

/// Decode the negative relative offset used by OFS_DELTA.
/// `buf` starts at the first byte right after the entry type/size header.
/// Returns (negative_distance, bytes_consumed).
pub fn parse_ofs_distance(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let mut c = first as u64;
    let mut val = c & 0x7f;
    let mut pos = 1usize;
    while c & 0x80 != 0 {
        val += 1;
        c = *buf.get(pos)? as u64;
        pos += 1;
        val = (val << 7) | (c & 0x7f);
    }
    Some((val, pos))
}

pub fn encode_ofs_distance(mut distance: u64) -> Vec<u8> {
    let mut bytes = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance > 0 {
        distance -= 1;
        bytes.push(((distance & 0x7f) as u8) | 0x80);
        distance >>= 7;
    }
    bytes.reverse();
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaKind {
    Insert,
    Copy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaCommand {
    pub kind: DeltaKind,
    /// Byte range of this command within the delta instruction stream.
    pub instr_start: usize,
    pub instr_end: usize,
    /// Copy offset/length (Copy only).
    pub copy_offset: usize,
    pub copy_length: usize,
    /// Insert data byte range within the delta payload (Insert only).
    pub data_start: usize,
    pub data_end: usize,
}

#[derive(Debug, Clone)]
pub struct AppliedDelta {
    pub output: Vec<u8>,
    pub commands: Vec<DeltaCommand>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeltaError {
    Truncated,
    BaseSizeMismatch { declared: u64, actual: usize },
    ResultSizeMismatch { declared: u64, actual: usize },
    CopyOutOfRange {
        offset: usize,
        length: usize,
        base_len: usize,
    },
    OutputTooLong,
    BadCopyOpcode,
}

/// Apply Git delta instructions to `base`, producing the reconstructed body.
///
/// `declared_base_size` / `declared_result_size` are the varints carried in the
/// delta stream; a mismatch with the actual base length or reconstructed output
/// length is a size spoof.
pub fn apply_delta(
    base: &[u8],
    instructions: &[u8],
    declared_base_size: u64,
    declared_result_size: u64,
    max_result: usize,
) -> Result<AppliedDelta, DeltaError> {
    if declared_base_size != base.len() as u64 {
        return Err(DeltaError::BaseSizeMismatch {
            declared: declared_base_size,
            actual: base.len(),
        });
    }
    if declared_result_size as usize > max_result {
        return Err(DeltaError::OutputTooLong);
    }

    let mut out = Vec::with_capacity(declared_result_size as usize);
    let mut commands = Vec::new();
    let mut p = 0usize;
    while p < instructions.len() {
        let opcode = instructions[p];
        let instr_start = p;
        p += 1;
        if opcode & 0x80 != 0 {
            // copy
            let mut offset: usize = 0;
            let mut length: usize = 0;
            for i in 0..4u8 {
                if opcode & (1 << i) != 0 {
                    let b = *instructions.get(p).ok_or(DeltaError::Truncated)?;
                    offset |= (b as usize) << (8 * i);
                    p += 1;
                }
            }
            for i in 0..3u8 {
                if opcode & (1 << (4 + i)) != 0 {
                    let b = *instructions.get(p).ok_or(DeltaError::Truncated)?;
                    length |= (b as usize) << (8 * i);
                    p += 1;
                }
            }
            if length == 0 {
                length = 0x10000;
            }
            let instr_end = p;
            if offset
                .checked_add(length)
                .map(|end| end > base.len())
                .unwrap_or(true)
            {
                return Err(DeltaError::CopyOutOfRange {
                    offset,
                    length,
                    base_len: base.len(),
                });
            }
            out.extend_from_slice(&base[offset..offset + length]);
            commands.push(DeltaCommand {
                kind: DeltaKind::Copy,
                instr_start,
                instr_end,
                copy_offset: offset,
                copy_length: length,
                data_start: 0,
                data_end: 0,
            });
        } else if opcode != 0 {
            // insert
            let len = opcode as usize;
            if p + len > instructions.len() {
                return Err(DeltaError::Truncated);
            }
            let data_start = p;
            out.extend_from_slice(&instructions[p..p + len]);
            p += len;
            commands.push(DeltaCommand {
                kind: DeltaKind::Insert,
                instr_start,
                instr_end: p,
                copy_offset: 0,
                copy_length: 0,
                data_start,
                data_end: data_start + len,
            });
        } else {
            return Err(DeltaError::BadCopyOpcode);
        }
        if out.len() > max_result {
            return Err(DeltaError::OutputTooLong);
        }
    }
    if out.len() as u64 != declared_result_size {
        return Err(DeltaError::ResultSizeMismatch {
            declared: declared_result_size,
            actual: out.len(),
        });
    }
    Ok(AppliedDelta {
        output: out,
        commands,
    })
}

/// Split the post-inflation payload of a delta entry into its header
/// (2 varints + optional 20-byte ref) and the instruction stream.
pub fn split_delta_payload(
    inflated: &[u8],
    delta_ty: GitType,
) -> Option<(u64, u64, usize, usize, Option<[u8; 20]>)> {
    let (base_size, n1) = parse_delta_size(inflated)?;
    let (result_size, n2) = parse_delta_size(&inflated[n1..])?;
    let mut p = n1 + n2;
    let mut ref_oid = None;
    if delta_ty == GitType::RefDelta {
        let oid = inflated.get(p..p + 20)?;
        let mut a = [0u8; 20];
        a.copy_from_slice(oid);
        ref_oid = Some(a);
        p += 20;
    }
    let instr_start = p;
    Some((base_size, result_size, n1 + n2, instr_start, ref_oid))
}

/// Heuristic: is this body mostly printable text?
pub fn looks_like_text(body: &[u8]) -> bool {
    let sample = &body[..body.len().min(2048)];
    if sample.is_empty() {
        return true;
    }
    let printable = sample
        .iter()
        .filter(|b| **b == b'\n' || **b == b'\t' || **b == b'\r' || b.is_ascii_graphic() || **b == b' ')
        .count();
    printable * 100 / sample.len() >= 85
}

pub fn preview(body: &[u8], limit: usize) -> String {
    let take = body.len().min(limit);
    let mut s = String::new();
    for &b in &body[..take] {
        if b == b'\n' || b == b'\t' || b == b'\r' || (b.is_ascii_graphic() && b != 0x7f) || b == b' '
        {
            s.push(b as char);
        } else {
            s.push('\u{fffd}');
        }
    }
    s
}
