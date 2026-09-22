use flate2::{Decompress, FlushDecompress};
use sha1::{Digest, Sha1};
use std::fmt;

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
    pub fn code(self) -> u8 {
        match self {
            GitType::Commit => 1,
            GitType::Tree => 2,
            GitType::Blob => 3,
            GitType::Tag => 4,
            GitType::OfsDelta => 6,
            GitType::RefDelta => 7,
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

    pub fn from_code(code: u8) -> Option<Self> {
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

    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "commit" => GitType::Commit,
            "tree" => GitType::Tree,
            "blob" => GitType::Blob,
            "tag" => GitType::Tag,
            _ => return None,
        })
    }
}

impl fmt::Display for GitType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone)]
pub struct RawInflate {
    pub data: Vec<u8>,
    pub input_len: usize,
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub entry_end: u64,
    pub header_len: usize,
    pub type_code: u8,
    pub object_type: GitType,
    pub expected_size: usize,
    pub negative_offset: Option<u64>,
    pub base_oid: Option<[u8; 20]>,
    pub payload: RawInflate,
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub checksum: [u8; 20],
    pub stored_checksum: [u8; 20],
    pub header_len: usize,
    pub content_end: usize,
    pub entry_errors: Vec<(u64, String)>,
}

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub offset: u64,
    pub oid: [u8; 20],
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct IdxFile {
    pub entries: Vec<IdxEntry>,
    pub fanout: [u32; 256],
    pub pack_checksum: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitError {
    Truncated(&'static str),
    BadSignature,
    UnsupportedVersion(u32),
    BadObjectType(u8),
    BadObjectHeader,
    InvalidZlib(String),
    SizeMismatch { expected: usize, actual: usize },
    TrailingZlibData,
    OffsetBeforePack,
    BadDelta(&'static str),
    BadChecksum,
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::Truncated(what) => write!(f, "truncated {what}"),
            GitError::BadSignature => f.write_str("bad signature"),
            GitError::UnsupportedVersion(v) => write!(f, "unsupported pack version {v}"),
            GitError::BadObjectType(c) => write!(f, "bad object type {c}"),
            GitError::BadObjectHeader => f.write_str("bad loose object header"),
            GitError::InvalidZlib(msg) => write!(f, "invalid zlib stream: {msg}"),
            GitError::SizeMismatch { expected, actual } => {
                write!(f, "declared size {expected} but inflated size {actual}")
            }
            GitError::TrailingZlibData => f.write_str("zlib stream ended before object end"),
            GitError::OffsetBeforePack => f.write_str("ofs-delta points before pack"),
            GitError::BadDelta(msg) => write!(f, "invalid delta: {msg}"),
            GitError::BadChecksum => f.write_str("checksum mismatch"),
        }
    }
}

impl std::error::Error for GitError {}

pub fn oid_hex(oid: &[u8; 20]) -> String {
    let mut out = String::with_capacity(40);
    for byte in oid {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn parse_oid(hex: &str) -> Option<[u8; 20]> {
    if hex.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn git_object_id(kind: GitType, data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(kind.name().as_bytes());
    hasher.update(b" ");
    hasher.update(data.len().to_string().as_bytes());
    hasher.update([0]);
    hasher.update(data);
    hasher.finalize().into()
}

pub fn pack_checksum(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn take<'a>(bytes: &'a [u8], at: usize, len: usize) -> Result<&'a [u8], GitError> {
    bytes.get(at..at + len).ok_or(GitError::Truncated("data"))
}

pub fn inflate_raw(bytes: &[u8], start: usize) -> Result<RawInflate, GitError> {
    let mut decoder = Decompress::new(true);
    let mut output = Vec::new();
    let mut chunk = vec![0u8; 4096];
    let mut consumed_total = 0usize;
    loop {
        let input = bytes
            .get(start + consumed_total..)
            .ok_or(GitError::Truncated("zlib input"))?;
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder
            .decompress(input, &mut chunk, FlushDecompress::None)
            .map_err(|err| GitError::InvalidZlib(err.to_string()))?;
        consumed_total = (decoder.total_in() - before_in) as usize + consumed_total;
        let written = (decoder.total_out() - before_out) as usize;
        output.extend_from_slice(&chunk[..written]);
        if status == flate2::Status::StreamEnd {
            break;
        }
        if status == flate2::Status::Ok && input.is_empty() {
            return Err(GitError::Truncated("zlib stream"));
        }
    }
    Ok(RawInflate { data: output, input_len: consumed_total })
}

pub fn parse_loose_object(bytes: &[u8]) -> Result<(GitType, Vec<u8>, usize), GitError> {
    let inflated = inflate_raw(bytes, 0)?;
    let output = inflated.data;
    let header_end = output
        .iter()
        .position(|b| *b == 0)
        .ok_or(GitError::BadObjectHeader)?;
    let header = std::str::from_utf8(&output[..header_end]).map_err(|_| GitError::BadObjectHeader)?;
    let (name, size_text) = header.split_once(' ').ok_or(GitError::BadObjectHeader)?;
    let kind = GitType::from_name(name).ok_or(GitError::BadObjectHeader)?;
    let expected_size = size_text.parse::<usize>().map_err(|_| GitError::BadObjectHeader)?;
    let mut data = output;
    let content = data.split_off(header_end + 1);
    let actual = content.len();
    if actual != expected_size {
        return Err(GitError::SizeMismatch { expected: expected_size, actual });
    }
    Ok((kind, content, inflated.input_len))
}

fn read_pack_header(bytes: &[u8]) -> Result<(usize, u32, u32), GitError> {
    let header = take(bytes, 0, 12)?;
    if &header[..4] != b"PACK" {
        return Err(GitError::BadSignature);
    }
    let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
    let count = u32::from_be_bytes(header[8..12].try_into().unwrap());
    if version != 2 {
        return Err(GitError::UnsupportedVersion(version));
    }
    Ok((12, version, count))
}

fn read_entry_header(bytes: &[u8], mut pos: usize) -> Result<(usize, u8, usize, usize, Option<u64>, Option<[u8; 20]>), GitError> {
    let first = *bytes.get(pos).ok_or(GitError::Truncated("entry header"))?;
    pos += 1;
    let type_code = (first >> 4) & 0b111;
    let object_type = GitType::from_code(type_code).ok_or(GitError::BadObjectType(type_code))?;
    let mut size = (first & 0x0f) as usize;
    let mut shift = 4u32;
    loop {
        let byte = *bytes.get(pos).ok_or(GitError::Truncated("size continuation"))?;
        pos += 1;
        size |= ((byte & 0x7f) as usize) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    let mut negative_offset = None;
    let mut base_oid = None;
    if object_type == GitType::OfsDelta {
        let byte = *bytes.get(pos).ok_or(GitError::Truncated("ofs-delta"))?;
        pos += 1;
        let mut distance = (byte & 0x7f) as u64;
        let mut current = byte;
        while current & 0x80 != 0 {
            current = *bytes.get(pos).ok_or(GitError::Truncated("ofs-delta continuation"))?;
            pos += 1;
            distance = ((distance.wrapping_add(1)) << 7) | (current & 0x7f) as u64;
        }
        negative_offset = Some(distance);
    } else if object_type == GitType::RefDelta {
        let raw = take(bytes, pos, 20)?;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(raw);
        pos += 20;
        base_oid = Some(oid);
    }
    Ok((pos, type_code, size, 0, negative_offset, base_oid))
}

pub fn parse_pack(bytes: &[u8]) -> Result<PackFile, GitError> {
    let (header_len, version, count) = read_pack_header(bytes)?;
    let mut entries = Vec::new();
    let mut entry_errors = Vec::new();
    let mut pos = header_len;
    for _ in 0..count {
        let offset = pos as u64;
        let (payload_start, type_code, expected_size, _, negative_offset, base_oid) =
            read_entry_header(bytes, pos)?;
        let header_len = payload_start - pos;
        let payload = match inflate_raw(bytes, payload_start) {
            Ok(payload) => payload,
            Err(err) => {
                entry_errors.push((offset, err.to_string()));
                if bytes.len() >= pos + 20 {
                    let mut stored_checksum = [0u8; 20];
                    stored_checksum.copy_from_slice(&bytes[bytes.len() - 20..]);
                    let mut checksum = [0u8; 20];
                    checksum.copy_from_slice(&pack_checksum(&bytes[..bytes.len() - 20]));
                    return Ok(PackFile { version, count, entries, checksum, stored_checksum, header_len, content_end: bytes.len() - 20, entry_errors });
                }
                return Err(err);
            }
        };
        let input_len = payload.input_len;
        let entry_end = (payload_start + input_len) as u64;
        let actual = payload.data.len();
        let object_type = GitType::from_code(type_code).unwrap();
        if actual != expected_size {
            entry_errors.push((offset, GitError::SizeMismatch { expected: expected_size, actual }.to_string()));
        }
        entries.push(PackEntry {
            offset,
            entry_end,
            header_len,
            type_code,
            object_type,
            expected_size,
            negative_offset,
            base_oid,
            payload,
        });
        pos = payload_start + input_len;
    }
    let stored = take(bytes, pos, 20)?;
    let mut stored_checksum = [0u8; 20];
    stored_checksum.copy_from_slice(stored);
    let mut checksum = [0u8; 20];
    checksum.copy_from_slice(&pack_checksum(&bytes[..pos]));
    Ok(PackFile {
        version,
        count,
        entries,
        checksum,
        stored_checksum,
        header_len,
        content_end: pos,
        entry_errors,
    })
}

pub struct DeltaInstruction {
    pub op_offset: usize,
    pub op_end: usize,
    pub kind: DeltaInstructionKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaInstructionKind {
    Insert { length: usize },
    Copy { offset: usize, length: usize },
}

pub struct AppliedDelta {
    pub base_size: usize,
    pub result_size: usize,
    pub instructions: Vec<DeltaInstruction>,
    pub data: Vec<u8>,
}

fn read_delta_size(delta: &[u8], mut pos: usize) -> Result<(usize, usize), GitError> {
    let mut size = 0usize;
    let mut shift = 0u32;
    loop {
        let byte = *delta.get(pos).ok_or(GitError::BadDelta("delta size"))?;
        pos += 1;
        size |= ((byte & 0x7f) as usize) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok((size, pos))
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<AppliedDelta, GitError> {
    let (base_size, pos) = read_delta_size(delta, 0)?;
    let (result_size, mut pos) = read_delta_size(delta, pos)?;
    if base_size != base.len() {
        return Err(GitError::BadDelta("base size does not match"));
    }
    let mut instructions = Vec::new();
    let mut output = Vec::with_capacity(result_size.min(64 * 1024 * 1024));
    while pos < delta.len() {
        let op_offset = pos;
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            let mut copy_offset = 0usize;
            let mut copy_length = 0usize;
            for bit in 0..4 {
                if op & (1 << bit) != 0 {
                    copy_offset |= (*delta.get(pos).ok_or(GitError::BadDelta("copy offset"))? as usize) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if op & (1 << (4 + bit)) != 0 {
                    copy_length |= (*delta.get(pos).ok_or(GitError::BadDelta("copy length"))? as usize) << (bit * 8);
                    pos += 1;
                }
            }
            if copy_length == 0 {
                copy_length = 0x10000;
            }
            if copy_offset.checked_add(copy_length).map_or(true, |end| end > base.len()) {
                return Err(GitError::BadDelta("copy outside base"));
            }
            output.extend_from_slice(&base[copy_offset..copy_offset + copy_length]);
            instructions.push(DeltaInstruction {
                op_offset,
                op_end: pos,
                kind: DeltaInstructionKind::Copy { offset: copy_offset, length: copy_length },
            });
        } else if op > 0 {
            let length = op as usize;
            if pos + length > delta.len() {
                return Err(GitError::BadDelta("insert outside delta"));
            }
            output.extend_from_slice(&delta[pos..pos + length]);
            pos += length;
            instructions.push(DeltaInstruction {
                op_offset,
                op_end: pos,
                kind: DeltaInstructionKind::Insert { length },
            });
        } else {
            return Err(GitError::BadDelta("reserved zero opcode"));
        }
    }
    if output.len() != result_size {
        return Err(GitError::BadDelta("result size does not match"));
    }
    Ok(AppliedDelta { base_size: base.len(), result_size, instructions, data: output })
}

fn u32_at(bytes: &[u8], pos: usize) -> u32 {
    u32::from_be_bytes(bytes[pos..pos + 4].try_into().unwrap())
}

pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub fn entry_crc32(pack: &[u8], entry: &PackEntry) -> u32 {
    let start = entry.offset as usize;
    let end = entry.entry_end as usize;
    crc32_ieee(pack.get(start..end).unwrap_or_default())
}

pub fn parse_idx(bytes: &[u8]) -> Result<IdxFile, GitError> {
    if bytes.len() < 8 + 1024 {
        return Err(GitError::Truncated("idx"));
    }
    if &bytes[..4] == b"\xfftOc" {
        if u32_at(bytes, 4) != 2 {
            return Err(GitError::UnsupportedVersion(u32_at(bytes, 4)));
        }
    } else {
        return Err(GitError::BadSignature);
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32_at(bytes, 8 + i * 4);
    }
    let count = fanout[255] as usize;
    let mut pos = 8 + 256 * 4;
    let mut oids = Vec::with_capacity(count);
    for _ in 0..count {
        let raw = take(bytes, pos, 20)?;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(raw);
        oids.push(oid);
        pos += 20;
    }
    let mut crcs = Vec::with_capacity(count);
    for _ in 0..count {
        crcs.push(u32_at(bytes, pos));
        pos += 4;
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let offset_value = u32_at(bytes, pos);
        pos += 4;
        let offset = if offset_value & 0x8000_0000 != 0 {
            let large_pos = 8 + 256 * 4 + count * 28 + (offset_value & 0x7fff_ffff) as usize * 8;
            u64::from_be_bytes(take(bytes, large_pos, 8)?.try_into().unwrap())
        } else {
            offset_value as u64
        };
        entries.push(IdxEntry { offset, oid: oids[i], crc32: crcs[i] });
    }
    let trailer_pos = 8 + 256 * 4 + count * 28;
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(take(bytes, trailer_pos, 20)?);
    let stored_idx_checksum = take(bytes, trailer_pos + 20, 20)?;
    let actual_idx_checksum = crate::git::pack_checksum(&bytes[..trailer_pos + 20]);
    if actual_idx_checksum.as_slice() != stored_idx_checksum {
        return Err(GitError::BadChecksum);
    }
    Ok(IdxFile { entries, fanout, pack_checksum })
}
