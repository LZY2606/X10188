use flate2::write::ZlibEncoder;
use flate2::Decompress;
use flate2::{Compression, FlushDecompress, Status};
use sha1::{Digest, Sha1};
use std::fmt;
use std::io::Write;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitError {
    TooShort(&'static str),
    BadSignature,
    UnsupportedVersion(u32),
    UnknownType(u8),
    BadDelta(&'static str),
    BadObject(&'static str),
    InvalidOffset,
    BadChecksum,
    Zlib(String),
}

#[derive(Debug, Clone)]
pub struct Inflated {
    pub data: Vec<u8>,
    pub consumed: usize,
    pub declared_len: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: usize,
    pub header_len: usize,
    pub object_type: ObjectType,
    pub declared_size: usize,
    pub payload_offset: usize,
    pub payload_end: usize,
    pub data: Vec<u8>,
    pub crc32: u32,
    pub negative_offset: Option<usize>,
    pub base_oid: Option<[u8; 20]>,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub data: Vec<u8>,
    pub entries: Vec<PackEntry>,
}

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub offset: usize,
    pub oid: [u8; 20],
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedIndex {
    pub fanout: Vec<u32>,
    pub entries: Vec<IndexEntry>,
    pub pack_checksum: [u8; 20],
    pub index_checksum: [u8; 20],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaOp {
    Insert {
        source_start: usize,
        source_end: usize,
        target_start: usize,
        target_end: usize,
    },
    Copy {
        base_start: usize,
        base_end: usize,
        target_start: usize,
        target_end: usize,
    },
}

#[derive(Debug, Clone)]
pub struct DeltaInstructions {
    pub source_size: usize,
    pub target_size: usize,
    pub instruction_bytes: usize,
    pub instruction_range_start: usize,
    pub instruction_range_end: usize,
    pub ops: Vec<DeltaOp>,
}

impl ObjectType {
    pub fn name(self) -> &'static str {
        match self {
            ObjectType::Commit => "commit",
            ObjectType::Tree => "tree",
            ObjectType::Blob => "blob",
            ObjectType::Tag => "tag",
            ObjectType::OfsDelta => "ofs-delta",
            ObjectType::RefDelta => "ref-delta",
        }
    }

    pub fn pack_code(self) -> Option<u8> {
        match self {
            ObjectType::Commit => Some(1),
            ObjectType::Tree => Some(2),
            ObjectType::Blob => Some(3),
            ObjectType::Tag => Some(4),
            ObjectType::OfsDelta => Some(6),
            ObjectType::RefDelta => Some(7),
        }
    }

    pub fn from_pack(code: u8) -> Result<Self, GitError> {
        match code {
            1 => Ok(ObjectType::Commit),
            2 => Ok(ObjectType::Tree),
            3 => Ok(ObjectType::Blob),
            4 => Ok(ObjectType::Tag),
            6 => Ok(ObjectType::OfsDelta),
            7 => Ok(ObjectType::RefDelta),
            other => Err(GitError::UnknownType(other)),
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, ObjectType::OfsDelta | ObjectType::RefDelta)
    }

    pub fn is_base(self) -> bool {
        matches!(
            self,
            ObjectType::Commit | ObjectType::Tree | ObjectType::Blob | ObjectType::Tag
        )
    }
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::TooShort(what) => write!(f, "truncated {what}"),
            GitError::BadSignature => f.write_str("bad signature"),
            GitError::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            GitError::UnknownType(code) => write!(f, "unknown pack object type {code}"),
            GitError::BadDelta(msg) => write!(f, "invalid delta: {msg}"),
            GitError::BadObject(msg) => write!(f, "invalid object: {msg}"),
            GitError::InvalidOffset => f.write_str("invalid ofs-delta distance"),
            GitError::BadChecksum => f.write_str("checksum mismatch"),
            GitError::Zlib(msg) => write!(f, "zlib error: {msg}"),
        }
    }
}

impl std::error::Error for GitError {}

pub fn oid_hex(oid: &[u8; 20]) -> String {
    hex::encode(oid)
}

pub fn parse_oid(text: &str) -> Option<[u8; 20]> {
    let bytes = hex::decode(text).ok()?;
    bytes.try_into().ok()
}

pub fn git_object_id(type_name: &str, content: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(type_name.as_bytes());
    hasher.update(b" ");
    hasher.update(content.len().to_string().as_bytes());
    hasher.update([0]);
    hasher.update(content);
    hasher.finalize().into()
}

pub fn object_header(type_name: &str, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(type_name.as_bytes());
    out.push(b' ');
    out.extend_from_slice(content.len().to_string().as_bytes());
    out.push(0);
    out.extend_from_slice(content);
    out
}

pub fn split_loose_object(data: &[u8]) -> Result<(ObjectType, Vec<u8>), GitError> {
    let nul = data
        .iter()
        .position(|b| *b == 0)
        .ok_or(GitError::BadObject("missing NUL header"))?;
    let header = std::str::from_utf8(&data[..nul])
        .map_err(|_| GitError::BadObject("non-UTF-8 header"))?;
    let (type_name, size_text) = header
        .split_once(' ')
        .ok_or(GitError::BadObject("malformed header"))?;
    let kind = match type_name {
        "commit" => Some(ObjectType::Commit),
        "tree" => Some(ObjectType::Tree),
        "blob" => Some(ObjectType::Blob),
        "tag" => Some(ObjectType::Tag),
        _ => None,
    }
    .ok_or(GitError::BadObject("unknown object type"))?;
    let declared = size_text
        .parse::<usize>()
        .map_err(|_| GitError::BadObject("bad size"))?;
    if declared != data.len() - nul - 1 {
        return Err(GitError::BadObject("declared size mismatch"));
    }
    Ok((kind, data[nul + 1..].to_vec()))
}

pub fn inflate_zlib(
    input: &[u8],
    start: usize,
    max_len: usize,
    declared_len: Option<usize>,
) -> Result<Inflated, GitError> {
    let mut decompressor = Decompress::new(true);
    let mut output = Vec::new();
    let mut consumed = 0usize;
    let mut status = Status::Ok;
    while status != Status::StreamEnd {
        if output.len() > max_len {
            return Err(GitError::BadObject("expanded object exceeds hard limit"));
        }
        let mut buf = [0u8; 16 * 1024];
        let total_out_before = decompressor.total_out();
        let result = decompressor.decompress(
            &input[start + consumed..],
            &mut buf,
            FlushDecompress::None,
        );
        consumed = decompressor.total_in() as usize;
        match result {
            Ok(next_status) => {
                let written = (decompressor.total_out() - total_out_before) as usize;
                output.extend_from_slice(&buf[..written]);
                status = next_status;
                if consumed > input.len() - start {
                    return Err(GitError::Zlib("consumed beyond buffer".into()));
                }
                if decompressor.total_in() == 0
                    && written == 0
                    && next_status != Status::StreamEnd
                {
                    return Err(GitError::Zlib("decompression made no progress".into()));
                }
            }
            Err(err) => return Err(GitError::Zlib(err.to_string())),
        }
    }
    if let Some(expected) = declared_len {
        if output.len() != expected {
            return Err(GitError::BadObject("declared size mismatch after inflate"));
        }
    }
    Ok(Inflated {
        data: output,
        consumed,
        declared_len,
    })
}

pub fn deflate_zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("Vec<u8> write cannot fail");
    encoder.finish().expect("zlib encoding cannot fail")
}

pub const HARD_EXPAND_LIMIT: usize = 256 * 1024 * 1024;

pub fn parse_pack(data: &[u8]) -> Result<ParsedPack, GitError> {
    if data.len() < 32 {
        return Err(GitError::TooShort("pack"));
    }
    if &data[..4] != b"PACK" {
        return Err(GitError::BadSignature);
    }
    let version = u32_be(data, 4);
    if version != 2 {
        return Err(GitError::UnsupportedVersion(version));
    }
    let expected_count = u32_be(data, 8) as usize;
    let mut entries = Vec::with_capacity(expected_count.min(1024 * 1024));
    let mut offset = 12;
    let trailer_offset = data.len() - 20;
    while offset < trailer_offset {
        if entries.len() >= expected_count {
            return Err(GitError::BadObject("more entries than pack header declares"));
        }
        let (mut entry, payload_offset) = read_pack_entry_header(data, offset)?;
        if entry.declared_size > HARD_EXPAND_LIMIT {
            return Err(GitError::BadObject("declared size exceeds hard limit"));
        }
        let inflated = inflate_zlib(
            data,
            payload_offset,
            entry.declared_size,
            Some(entry.declared_size),
        )?;
        let payload_end = payload_offset + inflated.consumed;
        if payload_end > trailer_offset {
            return Err(GitError::TooShort("pack entry payload"));
        }
        entry.payload_offset = payload_offset;
        entry.payload_end = payload_end;
        entry.data = inflated.data;
        entry.crc32 = crc32(&data[entry.offset..payload_end]);
        entries.push(entry);
        offset = payload_end;
    }
    if offset != trailer_offset || entries.len() != expected_count {
        return Err(GitError::BadObject("pack entry count or final offset mismatch"));
    }
    let mut hasher = Sha1::new();
    hasher.update(&data[..trailer_offset]);
    let actual: [u8; 20] = hasher.finalize().into();
    if actual != data[trailer_offset..] {
        return Err(GitError::BadChecksum);
    }
    Ok(ParsedPack {
        data: data.to_vec(),
        entries,
    })
}

fn read_delta_size(data: &[u8], offset: &mut usize) -> Result<usize, GitError> {
    let mut size = 0usize;
    let mut shift = 0;
    loop {
        let byte = *data
            .get(*offset)
            .ok_or(GitError::BadDelta("truncated size"))?;
        *offset += 1;
        size |= usize::from(byte & 0x7f) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }
    Ok(size)
}

pub fn parse_delta_instructions(data: &[u8]) -> Result<DeltaInstructions, GitError> {
    let mut offset = 0;
    let source_size = read_delta_size(data, &mut offset)?;
    let target_size = read_delta_size(data, &mut offset)?;
    let instruction_start = offset;
    let mut ops = Vec::new();
    let mut output_len = 0usize;
    while offset < data.len() {
        let opcode = data[offset];
        offset += 1;
        if opcode == 0 {
            return Err(GitError::BadDelta("zero opcode is reserved"));
        }
        if opcode & 0x80 != 0 {
            let mut copy_offset = 0usize;
            let mut copy_size = 0usize;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    copy_offset |= usize::from(data[offset]) << (bit * 8);
                    offset += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (bit + 4)) != 0 {
                    copy_size |= usize::from(data[offset]) << (bit * 8);
                    offset += 1;
                }
            }
            if copy_size == 0 {
                copy_size = 0x10000;
            }
            if copy_offset.checked_add(copy_size).ok_or(GitError::BadDelta("copy overflow"))?
                > source_size
            {
                return Err(GitError::BadDelta("copy reads outside base"));
            }
            if output_len
                .checked_add(copy_size)
                .ok_or(GitError::BadDelta("target overflow"))?
                > target_size
            {
                return Err(GitError::BadDelta("copy writes outside target"));
            }
            ops.push(DeltaOp::Copy {
                base_start: copy_offset,
                base_end: copy_offset + copy_size,
                target_start: output_len,
                target_end: output_len + copy_size,
            });
            output_len += copy_size;
        } else {
            let insert_len = usize::from(opcode & 0x7f);
            let source_start = offset;
            let source_end = offset
                .checked_add(insert_len)
                .ok_or(GitError::BadDelta("insert overflow"))?;
            if source_end > data.len() {
                return Err(GitError::BadDelta("insert reads outside delta"));
            }
            if output_len
                .checked_add(insert_len)
                .ok_or(GitError::BadDelta("target overflow"))?
                > target_size
            {
                return Err(GitError::BadDelta("insert writes outside target"));
            }
            ops.push(DeltaOp::Insert {
                source_start,
                source_end,
                target_start: output_len,
                target_end: output_len + insert_len,
            });
            output_len += insert_len;
            offset = source_end;
        }
    }
    if output_len != target_size {
        return Err(GitError::BadDelta("incomplete target output"));
    }
    Ok(DeltaInstructions {
        source_size,
        target_size,
        instruction_bytes: offset - instruction_start,
        instruction_range_start: instruction_start,
        instruction_range_end: offset,
        ops,
    })
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaInstructions), GitError> {
    let instructions = parse_delta_instructions(delta)?;
    if base.len() != instructions.source_size {
        return Err(GitError::BadDelta("source length does not match base"));
    }
    let mut out = vec![0u8; instructions.target_size];
    for op in &instructions.ops {
        match op {
            DeltaOp::Insert {
                source_start,
                source_end,
                target_start,
                target_end,
            } => out[*target_start..*target_end]
                .copy_from_slice(&delta[*source_start..*source_end]),
            DeltaOp::Copy {
                base_start,
                base_end,
                target_start,
                target_end,
            } => out[*target_start..*target_end]
                .copy_from_slice(&base[*base_start..*base_end]),
        }
    }
    Ok((out, instructions))
}

pub fn parse_index(data: &[u8]) -> Result<ParsedIndex, GitError> {
    if data.len() < 8 {
        return Err(GitError::TooShort("index"));
    }
    if &data[..4] != b"\xfftOc" {
        return Err(GitError::BadSignature);
    }
    let version = u32_be(data, 4);
    if version != 2 {
        return Err(GitError::UnsupportedVersion(version));
    }
    let fanout = (0..256).map(|i| u32_be(data, 8 + i * 4)).collect::<Vec<_>>();
    let count = *fanout.last().unwrap() as usize;
    let oid_base = 8 + 1024;
    let crc_base = oid_base + count * 20;
    let offset_base = crc_base + count * 4;
    let raw_offsets = (0..count)
        .map(|i| u32_be(data, offset_base + i * 4))
        .collect::<Vec<_>>();
    let large_base = offset_base + count * 4;
    let large_count = raw_offsets
        .iter()
        .filter(|raw| **raw & 0x8000_0000 != 0)
        .count();
    if data.len() != large_base + large_count * 8 + 40 {
        return Err(GitError::BadObject("unexpected index table length"));
    }
    let mut entries = Vec::with_capacity(count);
    for (i, raw_offset) in raw_offsets.into_iter().enumerate() {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[oid_base + i * 20..oid_base + (i + 1) * 20]);
        let offset = if raw_offset & 0x8000_0000 != 0 {
            let large_index = (raw_offset & 0x7fff_ffff) as usize;
            let at = large_base + large_index * 8;
            u64::from_be_bytes(data[at..at + 8].try_into().unwrap()) as usize
        } else {
            raw_offset as usize
        };
        entries.push(IndexEntry {
            offset,
            oid,
            crc32: u32_be(data, crc_base + i * 4),
        });
    }
    let checksum_base = large_base + large_count * 8;
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&data[checksum_base..checksum_base + 20]);
    let mut index_checksum = [0u8; 20];
    index_checksum.copy_from_slice(&data[checksum_base + 20..checksum_base + 40]);
    let mut hasher = Sha1::new();
    hasher.update(&data[..checksum_base + 20]);
    let actual_index: [u8; 20] = hasher.finalize().into();
    if actual_index != index_checksum {
        return Err(GitError::BadChecksum);
    }
    if fanout[255] as usize != entries.len()
        || fanout.windows(2).any(|pair| pair[0] > pair[1])
        || fanout[0] > fanout[255]
    {
        return Err(GitError::BadObject("invalid fanout table"));
    }
    Ok(ParsedIndex { fanout, entries, pack_checksum, index_checksum })
}

pub fn parse_loose(data: &[u8]) -> Result<(ObjectType, Vec<u8>, usize), GitError> {
    let inflated = inflate_zlib(data, 0, HARD_EXPAND_LIMIT, None)?;
    let (kind, content) = split_loose_object(&inflated.data)?;
    Ok((kind, content, inflated.consumed))
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

fn u32_be(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn read_pack_entry_header(data: &[u8], mut offset: usize) -> Result<(PackEntry, usize), GitError> {
    let first = *data.get(offset).ok_or(GitError::TooShort("pack entry"))?;
    let object_type = ObjectType::from_pack((first >> 4) & 7)?;
    let mut size = usize::from(first & 0x0f);
    let mut shift = 4;
    let start = offset;
    offset += 1;
    let mut continuation = first & 0x80 != 0;
    while continuation {
        let byte = *data.get(offset).ok_or(GitError::TooShort("pack size"))?;
        size |= usize::from(byte & 0x7f) << shift;
        shift += 7;
        continuation = byte & 0x80 != 0;
        offset += 1;
    }

    let mut negative_offset = None;
    let mut base_oid = None;
    if object_type == ObjectType::OfsDelta {
        let first = *data.get(offset).ok_or(GitError::TooShort("ofs-delta"))?;
        let mut distance = usize::from(first & 0x7f);
        offset += 1;
        let mut current = first;
        while current & 0x80 != 0 {
            let next = *data.get(offset).ok_or(GitError::TooShort("ofs-delta"))?;
            distance = distance.wrapping_add(1);
            distance = distance.checked_shl(7).ok_or(GitError::InvalidOffset)?;
            distance |= usize::from(next & 0x7f);
            offset += 1;
            current = next;
        }
        negative_offset = Some(distance);
    } else if object_type == ObjectType::RefDelta {
        let oid_bytes = data
            .get(offset..offset + 20)
            .ok_or(GitError::TooShort("ref-delta base OID"))?;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(oid_bytes);
        base_oid = Some(oid);
        offset += 20;
    }

    let entry = PackEntry {
        offset: start,
        header_len: offset - start,
        object_type,
        declared_size: size,
        payload_offset: offset,
        payload_end: 0,
        data: Vec::new(),
        crc32: 0,
        negative_offset,
        base_oid,
    };
    Ok((entry, offset))
}
