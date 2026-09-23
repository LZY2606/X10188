use sha1::{Digest, Sha1};
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl GitType {
    pub fn from_pack(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Commit),
            2 => Some(Self::Tree),
            3 => Some(Self::Blob),
            4 => Some(Self::Tag),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "commit" => Some(Self::Commit),
            "tree" => Some(Self::Tree),
            "blob" => Some(Self::Blob),
            "tag" => Some(Self::Tag),
            _ => None,
        }
    }
}

pub fn git_object_id(kind: GitType, payload: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(kind.name().as_bytes());
    hasher.update(b" ");
    hasher.update(payload.len().to_string().as_bytes());
    hasher.update([0]);
    hasher.update(payload);
    hasher.finalize().into()
}

pub fn read_pack_size(first: u8, rest: &[u8]) -> Result<(u64, usize), String> {
    let mut size = u64::from(first & 0x7f);
    let mut shift = 7;
    let mut used = 0;
    for &byte in rest {
        used += 1;
        size |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((size, used));
        }
        shift += 7;
        if shift > 63 {
            return Err("pack size varint is too long".into());
        }
    }
    Err("truncated pack size varint".into())
}

pub fn read_delta_size(bytes: &[u8]) -> Result<(u64, usize), String> {
    let mut size = 0u64;
    let mut shift = 0;
    let mut used = 0;
    for &byte in bytes {
        used += 1;
        size |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok((size, used));
        }
        shift += 7;
        if shift > 63 {
            return Err("delta size varint is too long".into());
        }
    }
    Err("truncated delta size varint".into())
}

pub fn encode_delta_size(mut size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (size as u8) & 0x7f;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if size == 0 {
            return out;
        }
    }
}

pub fn encode_pack_header(kind: u8, mut size: u64) -> Vec<u8> {
    let mut first = (size as u8) & 0x0f;
    size >>= 4;
    if size != 0 {
        first |= 0x80;
    }
    first |= kind << 4;
    let mut out = vec![first];
    while size != 0 {
        let mut byte = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaOp {
    pub opcode: String,
    pub range_start: usize,
    pub range_end: usize,
    pub base_offset: Option<usize>,
    pub base_len: Option<usize>,
    pub insert_len: Option<usize>,
    pub output_before: usize,
    pub output_after: usize,
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, Vec<DeltaOp>), String> {
    let (source_size, pos1) = read_delta_size(delta)?;
    if source_size as usize != base.len() {
        return Err(format!(
            "delta source size {} does not match base length {}",
            source_size,
            base.len()
        ));
    }
    let (target_size, pos2) = read_delta_size(&delta[pos1..])?;
    let mut pos = pos1 + pos2;
    let mut out = Vec::with_capacity(target_size as usize);
    let mut ops = Vec::new();
    while pos < delta.len() {
        let op_start = pos;
        let instruction = delta[pos];
        pos += 1;
        let output_before = out.len();
        if instruction == 0 {
            return Err("delta opcode 0 is reserved".into());
        }
        if instruction & 0x80 != 0 {
            let mut offset = 0usize;
            let mut size = 0usize;
            for bit in 0..4 {
                if instruction & (1 << bit) != 0 {
                    offset |= usize::from(delta[pos]) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if instruction & (1 << (4 + bit)) != 0 {
                    size |= usize::from(delta[pos]) << (bit * 8);
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            if offset.checked_add(size).map(|end| end > base.len()).unwrap_or(true) {
                return Err(format!(
                    "copy instruction reads base range {}..{} outside base length {}",
                    offset,
                    offset + size,
                    base.len()
                ));
            }
            if out.len() as u64 + size as u64 > target_size {
                return Err("copy instruction exceeds declared target size".into());
            }
            out.extend_from_slice(&base[offset..offset + size]);
            ops.push(DeltaOp {
                opcode: "copy".into(),
                range_start: op_start,
                range_end: pos,
                base_offset: Some(offset),
                base_len: Some(size),
                insert_len: None,
                output_before,
                output_after: out.len(),
            });
        } else {
            let size = instruction as usize;
            if pos + size > delta.len() {
                return Err("insert instruction runs past delta stream".into());
            }
            if out.len() + size > target_size as usize {
                return Err("insert instruction exceeds declared target size".into());
            }
            out.extend_from_slice(&delta[pos..pos + size]);
            pos += size;
            ops.push(DeltaOp {
                opcode: "insert".into(),
                range_start: op_start,
                range_end: pos,
                base_offset: None,
                base_len: None,
                insert_len: Some(size),
                output_before,
                output_after: out.len(),
            });
        }
    }
    if out.len() as u64 != target_size {
        return Err(format!(
            "delta target size {} does not match produced length {}",
            target_size,
            out.len()
        ));
    }
    Ok((out, ops))
}

pub fn inflate_zlib(bytes: &[u8]) -> Result<(Vec<u8>, usize), String> {
    let mut decoder = flate2::read::ZlibDecoder::new(std::io::Cursor::new(bytes));
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|err| format!("zlib stream failed: {err}"))?;
    let consumed = decoder.total_in() as usize;
    if consumed == 0 || consumed > bytes.len() {
        return Err("zlib decoder reported an invalid boundary".into());
    }
    Ok((out, consumed))
}
