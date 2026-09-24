use flate2::DecompressError;
use std::array::TryFromSliceError;
use std::fmt;
use std::io;

pub const SHA1_SIZE: usize = 20;
pub const SHA256_SIZE: usize = 32;
pub const PACK_SIGNATURE: [u8; 4] = *b"PACK";
pub const IDX_SIGNATURE: [u8; 4] = *b"\xfftOc";

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

    pub fn header_name(self) -> Option<&'static str> {
        match self {
            GitType::Commit => Some("commit"),
            GitType::Tree => Some("tree"),
            GitType::Blob => Some("blob"),
            GitType::Tag => Some("tag"),
            GitType::OfsDelta | GitType::RefDelta => None,
        }
    }

    fn pack_code(self) -> u8 {
        match self {
            GitType::Commit => 1,
            GitType::Tree => 2,
            GitType::Blob => 3,
            GitType::Tag => 4,
            GitType::OfsDelta => 6,
            GitType::RefDelta => 7,
        }
    }

    fn from_pack_code(code: u8) -> Result<Self, GitError> {
        match code {
            1 => Ok(GitType::Commit),
            2 => Ok(GitType::Tree),
            3 => Ok(GitType::Blob),
            4 => Ok(GitType::Tag),
            6 => Ok(GitType::OfsDelta),
            7 => Ok(GitType::RefDelta),
            _ => Err(GitError::Parse(format!("unsupported pack type {code}"))),
        }
    }

    fn from_header(value: &[u8]) -> Result<Self, GitError> {
        match value {
            b"commit" => Ok(GitType::Commit),
            b"tree" => Ok(GitType::Tree),
            b"blob" => Ok(GitType::Blob),
            b"tag" => Ok(GitType::Tag),
            _ => Err(GitError::Parse(format!("unknown object type {}", String::from_utf8_lossy(value)))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitError {
    Parse(String),
    Zlib(String),
    Io(String),
    Checksum(String),
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GitError::Parse(value) => write!(f, "parse error: {value}"),
            GitError::Zlib(value) => write!(f, "zlib error: {value}"),
            GitError::Io(value) => write!(f, "io error: {value}"),
            GitError::Checksum(value) => write!(f, "checksum error: {value}"),
        }
    }
}

impl std::error::Error for GitError {}

impl From<io::Error> for GitError {
    fn from(value: io::Error) -> Self {
        GitError::Io(value.to_string())
    }
}

impl From<DecompressError> for GitError {
    fn from(value: DecompressError) -> Self {
        GitError::Zlib(value.to_string())
    }
}

impl From<TryFromSliceError> for GitError {
    fn from(value: TryFromSliceError) -> Self {
        GitError::Parse(value.to_string())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashKind {
    Sha1,
    Sha256,
}

impl HashKind {
    pub fn size(self) -> usize {
        match self {
            HashKind::Sha1 => SHA1_SIZE,
            HashKind::Sha256 => SHA256_SIZE,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            HashKind::Sha1 => "sha1",
            HashKind::Sha256 => "sha256",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackVersion {
    pub number: u32,
    pub hash: HashKind,
}

#[derive(Debug, Clone)]
pub struct PackHeader {
    pub version: PackVersion,
    pub object_count: u32,
    pub header_end: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaRef {
    Offset(u64),
    Oid([u8; SHA1_SIZE]),
}

#[derive(Debug, Clone)]
pub struct PackObjectHeader {
    pub object_type: GitType,
    pub declared_size: u64,
    pub header_end: usize,
    pub delta_ref: Option<DeltaRef>,
}

#[derive(Debug, Clone)]
pub struct ZlibBoundary {
    pub input_start: usize,
    pub input_end: usize,
    pub output_start: u64,
    pub output_len: u64,
    pub expected_size: u64,
}

#[derive(Debug, Clone)]
pub struct PackObjectSpan {
    pub offset: u64,
    pub next_offset: u64,
    pub header: PackObjectHeader,
    pub zlib: ZlibBoundary,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct PackInfo {
    pub path: String,
    pub header: PackHeader,
    pub objects: Vec<PackObjectSpan>,
    pub checksum_offset: u64,
    pub actual_checksum: Vec<u8>,
    pub expected_checksum: Vec<u8>,
    pub checksum_valid: bool,
}

#[derive(Debug, Clone)]
pub struct LooseObject {
    pub expected_oid: [u8; SHA1_SIZE],
    pub object_type: GitType,
    pub declared_size: u64,
    pub zlib_start: usize,
    pub zlib_end: usize,
    pub data: Vec<u8>,
    pub actual_oid: [u8; SHA1_SIZE],
    pub oid_valid: bool,
}

#[derive(Debug, Clone)]
pub struct IndexEntry {
    pub oid: [u8; SHA1_SIZE],
    pub pack_offset: u64,
    pub crc32: u32,
    pub sorted_index: usize,
}

#[derive(Debug, Clone)]
pub struct IndexInfo {
    pub path: String,
    pub fanout: [u32; 256],
    pub entries: Vec<IndexEntry>,
    pub pack_checksum: [u8; SHA1_SIZE],
    pub index_checksum: [u8; SHA1_SIZE],
    pub pack_checksum_actual: Option<[u8; SHA1_SIZE]>,
    pub index_checksum_valid: bool,
    pub pack_checksum_valid: bool,
}

pub fn read_u32_be(input: &[u8], offset: usize) -> Result<u32, GitError> {
    Ok(u32::from_be_bytes(input.get(offset..offset + 4).ok_or_else(|| {
        GitError::Parse("unexpected end while reading u32".to_string())
    })?.try_into()?))
}

pub fn parse_pack_header(input: &[u8]) -> Result<PackHeader, GitError> {
    if input.len() < 12 {
        return Err(GitError::Parse("pack shorter than 12 byte header".to_string()));
    }
    if input[0..4] != PACK_SIGNATURE {
        return Err(GitError::Parse("missing PACK signature".to_string()));
    }
    let number = read_u32_be(input, 4)?;
    let hash = match number {
        2 => HashKind::Sha1,
        3 => HashKind::Sha256,
        _ => return Err(GitError::Parse(format!("unsupported pack version {number}"))),
    };
    let object_count = read_u32_be(input, 8)?;
    Ok(PackHeader { version: PackVersion { number, hash }, object_count, header_end: 12 })
}

pub fn read_size_encoding(input: &[u8], mut offset: usize) -> Result<(u64, usize), GitError> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        let byte = *input.get(offset).ok_or_else(|| GitError::Parse("truncated size encoding".to_string()))?;
        if shift >= 64 && byte & 0x7f != 0 {
            return Err(GitError::Parse("size encoding overflow".to_string()));
        }
        value |= u64::from(byte & 0x7f).checked_shl(shift).ok_or_else(|| GitError::Parse("size encoding overflow".to_string()))?;
        offset += 1;
        if byte & 0x80 == 0 {
            return Ok((value, offset));
        }
        shift += 7;
    }
}

pub fn parse_pack_object_header(input: &[u8], offset: usize) -> Result<PackObjectHeader, GitError> {
    let first = *input.get(offset).ok_or_else(|| GitError::Parse("missing object header".to_string()))?;
    let object_type = GitType::from_pack_code((first >> 4) & 7)?;
    let mut declared_size = u64::from(first & 0x0f);
    let mut pos = offset + 1;
    if first & 0x80 != 0 {
        let (rest, next) = read_size_encoding(input, pos)?;
        declared_size = declared_size
            .checked_add(rest.checked_shl(4).ok_or_else(|| GitError::Parse("pack object size overflow".to_string()))?)
            .ok_or_else(|| GitError::Parse("pack object size overflow".to_string()))?;
        pos = next;
    }
    let mut delta_ref = None;
    if object_type == GitType::OfsDelta {
        let byte = *input.get(pos).ok_or_else(|| GitError::Parse("missing ofs-delta distance".to_string()))?;
        let mut distance = u64::from(byte & 0x7f);
        pos += 1;
        let mut current = byte;
        while current & 0x80 != 0 {
            current = *input.get(pos).ok_or_else(|| GitError::Parse("truncated ofs-delta distance".to_string()))?;
            distance = distance.wrapping_add(1).checked_shl(7).ok_or_else(|| GitError::Parse("ofs-delta distance overflow".to_string()))?;
            distance |= u64::from(current & 0x7f);
            pos += 1;
        }
        let base_offset = u64::try_from(offset).map_err(|_| GitError::Parse("offset overflow".to_string()))?.checked_sub(distance)
            .ok_or_else(|| GitError::Parse("ofs-delta points before pack start".to_string()))?;
        delta_ref = Some(DeltaRef::Offset(base_offset));
    } else if object_type == GitType::RefDelta {
        let end = pos + SHA1_SIZE;
        let oid_slice = input.get(pos..end).ok_or_else(|| GitError::Parse("truncated ref-delta oid".to_string()))?;
        let mut oid = [0u8; SHA1_SIZE];
        oid.copy_from_slice(oid_slice);
        delta_ref = Some(DeltaRef::Oid(oid));
        pos = end;
    }
    Ok(PackObjectHeader { object_type, declared_size, header_end: pos, delta_ref })
}

pub fn inflate_limited(input: &[u8], start: usize, expected_size: u64, max_bytes: u64) -> Result<(Vec<u8>, usize), GitError> {
    if expected_size > max_bytes {
        return Err(GitError::Parse(format!("declared size {expected_size} exceeds limit {max_bytes}")));
    }
    let cap = usize::try_from(expected_size.min(max_bytes)).unwrap_or(usize::MAX);
    let mut output = Vec::with_capacity(cap.min(64 * 1024 * 1024));
    let mut decompressor = flate2::Decompress::new(true);
    let mut input_offset = start;
    loop {
        let output_before = output.len();
        let spare = max_bytes.saturating_sub(output.len() as u64);
        if spare == 0 {
            return Err(GitError::Parse(format!("decompressed stream exceeds limit {max_bytes}")));
        }
        let grow = (spare as usize).min(64 * 1024).max(1);
        output.resize(output_before + grow, 0);
        let input_before = decompressor.total_in();
        let result = decompressor.decompress(
            input.get(input_offset..).unwrap_or(&[]),
            &mut output[output_before..],
            flate2::FlushDecompress::None,
        )?;
        let consumed = (decompressor.total_in() - input_before) as usize;
        input_offset += consumed;
        output.truncate(output_before + (decompressor.total_out() as usize - output_before));
        if result == flate2::Status::StreamEnd {
            break;
        }
        if result == flate2::Status::Ok && consumed == 0 && decompressor.total_out() as usize == output_before {
            return Err(GitError::Zlib("decompressor made no progress".to_string()));
        }
    }
    if output.len() as u64 != expected_size {
        return Err(GitError::Parse(format!("size deception: header says {expected_size}, stream produced {}", output.len())));
    }
    Ok((output, input_offset))
}

fn sha1_digest(data: &[u8]) -> [u8; SHA1_SIZE] {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn git_object_id(object_type: GitType, data: &[u8]) -> Result<[u8; SHA1_SIZE], GitError> {
    let name = object_type.header_name().ok_or_else(|| GitError::Parse("delta data has no standalone object id".to_string()))?;
    let mut framed = Vec::with_capacity(name.len() + data.len() + 16);
    framed.extend_from_slice(name.as_bytes());
    framed.push(b' ');
    framed.extend_from_slice(data.len().to_string().as_bytes());
    framed.push(0);
    framed.extend_from_slice(data);
    Ok(sha1_digest(&framed))
}

pub fn parse_pack(input: &[u8], path: impl Into<String>, max_object_bytes: u64) -> Result<PackInfo, GitError> {
    let header = parse_pack_header(input)?;
    let hash_size = header.version.hash.size();
    let minimum_end = header.header_end + hash_size;
    if input.len() < minimum_end {
        return Err(GitError::Parse("pack too short for trailing checksum".to_string()));
    }
    let checksum_offset = input.len() - hash_size;
    let expected_checksum = input[checksum_offset..].to_vec();
    let actual_checksum = sha1_digest(&input[..checksum_offset]).to_vec();
    if header.version.number == 3 {
        return Err(GitError::Parse("pack v3 is not supported yet".to_string()));
    }
    let mut objects = Vec::with_capacity(header.object_count as usize);
    let mut offset = header.header_end;
    for ordinal in 0..header.object_count {
        let object_offset = offset;
        let object_header = parse_pack_object_header(input, offset)?;
        let (data, next_offset) = inflate_limited(input, object_header.header_end, object_header.declared_size, max_object_bytes)?;
        objects.push(PackObjectSpan {
            offset: object_offset as u64,
            next_offset: next_offset as u64,
            header: object_header,
            zlib: ZlibBoundary {
                input_start: object_header.header_end,
                input_end: next_offset,
                output_start: 0,
                output_len: data.len() as u64,
                expected_size: object_header.declared_size,
            },
            data,
        });
        offset = next_offset;
        let _ = ordinal;
    }
    if offset != checksum_offset {
        return Err(GitError::Parse(format!("object stream ends at {offset}, checksum starts at {checksum_offset}")));
    }
    Ok(PackInfo {
        path: path.into(),
        header,
        objects,
        checksum_offset: checksum_offset as u64,
        actual_checksum,
        expected_checksum,
        checksum_valid: expected_checksum == actual_checksum,
    })
}

pub fn parse_loose(input: &[u8], expected_oid: [u8; SHA1_SIZE], max_object_bytes: u64) -> Result<LooseObject, GitError> {
    let nul = input.iter().position(|value| *value == 0).ok_or_else(|| GitError::Parse("loose object missing NUL header".to_string()))?;
    let mut parts = input[..nul].splitn(2, |value| *value == b' ');
    let type_bytes = parts.next().ok_or_else(|| GitError::Parse("loose object missing type".to_string()))?;
    let size_bytes = parts.next().ok_or_else(|| GitError::Parse("loose object missing size".to_string()))?;
    let object_type = GitType::from_header(type_bytes)?;
    let declared_size = std::str::from_utf8(size_bytes).map_err(|error| GitError::Parse(error.to_string()))?
        .parse::<u64>().map_err(|error| GitError::Parse(error.to_string()))?;
    let (data, zlib_end) = inflate_limited(input, nul + 1, declared_size, max_object_bytes)?;
    if zlib_end != input.len() {
        return Err(GitError::Parse(format!("trailing {} bytes after loose zlib stream", input.len() - zlib_end)));
    }
    let actual_oid = git_object_id(object_type, &data)?;
    Ok(LooseObject {
        expected_oid,
        object_type,
        declared_size,
        zlib_start: nul + 1,
        zlib_end,
        data,
        actual_oid,
        oid_valid: actual_oid == expected_oid,
    })
}

pub fn parse_index(input: &[u8], path: impl Into<String>, pack: Option<&PackInfo>) -> Result<IndexInfo, GitError> {
    if input.len() < 8 {
        return Err(GitError::Parse("index shorter than header".to_string()));
    }
    let v2 = input[0..4] == IDX_SIGNATURE;
    if v2 && read_u32_be(input, 4)? != 2 {
        return Err(GitError::Parse("only idx v2 is supported".to_string()));
    }
    if !v2 {
        return Err(GitError::Parse("only idx v2 is supported".to_string()));
    }
    let fanout_start = 8;
    let mut fanout = [0u32; 256];
    for index in 0..256 {
        fanout[index] = read_u32_be(input, fanout_start + index * 4)?;
    }
    for index in 1..256 {
        if fanout[index] < fanout[index - 1] {
            return Err(GitError::Parse("non-monotonic fanout table".to_string()));
        }
    }
    let count = fanout[255] as usize;
    let mut pos = fanout_start + 256 * 4;
    let oid_end = pos.checked_add(count * SHA1_SIZE).ok_or_else(|| GitError::Parse("index table overflow".to_string()))?;
    let mut oids = Vec::with_capacity(count);
    let raw = input.get(pos..oid_end).ok_or_else(|| GitError::Parse("truncated index oid table".to_string()))?;
    for item in raw.chunks_exact(SHA1_SIZE) {
        let mut oid = [0u8; SHA1_SIZE];
        oid.copy_from_slice(item);
        oids.push(oid);
    }
    pos = oid_end;
    let crc_end = pos + count * 4;
    let mut crcs = Vec::with_capacity(count);
    for index in 0..count {
        crcs.push(read_u32_be(input, pos + index * 4)?);
    }
    pos = crc_end;
    let offsets_end = pos + count * 4;
    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let value = read_u32_be(input, pos + index * 4)?;
        if value & 0x8000_0000 != 0 {
            return Err(GitError::Parse("large pack offset table is not supported".to_string()));
        }
        entries.push(IndexEntry { oid: oids[index], pack_offset: u64::from(value), crc32: crcs[index], sorted_index: index });
    }
    pos = offsets_end;
    pos = pos.checked_add(count * 4 * 2).ok_or_else(|| GitError::Parse("large offset table overflow".to_string()))?;
    let pack_checksum_slice = input.get(pos..pos + SHA1_SIZE).ok_or_else(|| GitError::Parse("missing pack checksum in index".to_string()))?;
    let mut pack_checksum = [0u8; SHA1_SIZE];
    pack_checksum.copy_from_slice(pack_checksum_slice);
    let index_checksum_slice = input.get(pos + SHA1_SIZE..pos + SHA1_SIZE * 2).ok_or_else(|| GitError::Parse("missing index checksum".to_string()))?;
    let mut index_checksum = [0u8; SHA1_SIZE];
    index_checksum.copy_from_slice(index_checksum_slice);
    if input.len() != pos + SHA1_SIZE * 2 {
        return Err(GitError::Parse("trailing bytes after index".to_string()));
    }
    let index_checksum_actual = sha1_digest(&input[..pos + SHA1_SIZE]);
    let pack_checksum_actual = pack.map(|value| {
        let mut digest = [0u8; SHA1_SIZE];
        digest.copy_from_slice(&value.actual_checksum);
        digest
    });
    for (bucket, end) in fanout.iter().enumerate() {
        let actual = oids.iter().filter(|oid| oid[0] as usize <= bucket).count();
        if actual != *end as usize {
            return Err(GitError::Parse(format!("fanout bucket {bucket} is inconsistent")));
        }
    }
    for pair in oids.windows(2) {
        if pair[0] >= pair[1] {
            return Err(GitError::Parse("index oids are not strictly sorted and unique".to_string()));
        }
    }
    if let Some(pack_info) = pack {
        let mut offsets: Vec<u64> = entries.iter().map(|entry| entry.pack_offset).collect();
        offsets.sort_unstable();
        let actual: Vec<u64> = pack_info.objects.iter().map(|object| object.offset).collect();
        if offsets != actual {
            return Err(GitError::Parse("index offsets do not match pack object layout".to_string()));
        }
    }
    Ok(IndexInfo {
        path: path.into(),
        fanout,
        entries,
        pack_checksum,
        index_checksum,
        pack_checksum_actual,
        index_checksum_valid: index_checksum == index_checksum_actual,
        pack_checksum_valid: pack_checksum_actual.map(|actual| actual == pack_checksum).unwrap_or(false),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaInstructionRange {
    pub delta_offset: u64,
    pub length: u64,
    pub kind: &'static str,
    pub copy_offset: Option<u64>,
    pub copy_size: Option<u64>,
    pub insert_size: Option<u64>,
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, Vec<DeltaInstructionRange>), GitError> {
    let (base_size, mut pos) = read_size_encoding(delta, 0)?;
    if base_size as usize != base.len() {
        return Err(GitError::Parse(format!("delta expects base size {base_size}, got {}", base.len())));
    }
    let (result_size, after_result_size) = read_size_encoding(delta, pos)?;
    let mut instructions = Vec::new();
    pos = after_result_size;
    let mut output = Vec::new();
    while pos < delta.len() {
        let opcode = delta[pos];
        let start = pos;
        pos += 1;
        if opcode == 0 {
            return Err(GitError::Parse("invalid delta opcode 0".to_string()));
        }
        if opcode & 0x80 != 0 {
            let mut copy_offset = 0u64;
            let mut copy_size = 0u64;
            for bit in 0..4 {
                if opcode & (1 << bit) != 0 {
                    copy_offset |= u64::from(delta.get(pos).copied().ok_or_else(|| GitError::Parse("truncated copy offset".to_string()))?) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (bit + 4)) != 0 {
                    copy_size |= u64::from(delta.get(pos).copied().ok_or_else(|| GitError::Parse("truncated copy size".to_string()))?) << (bit * 8);
                    pos += 1;
                }
            }
            if copy_size == 0 {
                copy_size = 0x10000;
            }
            let end = copy_offset.checked_add(copy_size).ok_or_else(|| GitError::Parse("copy range overflow".to_string()))?;
            if end > base.len() as u64 {
                return Err(GitError::Parse(format!("copy {copy_offset}+{copy_size} exceeds base {}", base.len())));
            }
            output.extend_from_slice(&base[copy_offset as usize..end as usize]);
            instructions.push(DeltaInstructionRange { delta_offset: start as u64, length: (pos - start) as u64, kind: "copy", copy_offset: Some(copy_offset), copy_size: Some(copy_size), insert_size: None });
        } else {
            let insert_size = usize::from(opcode);
            if pos + insert_size > delta.len() {
                return Err(GitError::Parse("truncated insert payload".to_string()));
            }
            output.extend_from_slice(&delta[pos..pos + insert_size]);
            instructions.push(DeltaInstructionRange { delta_offset: start as u64, length: (pos - start + insert_size) as u64, kind: "insert", copy_offset: None, copy_size: None, insert_size: Some(insert_size as u64) });
            pos += insert_size;
        }
        if output.len() as u64 > result_size {
            return Err(GitError::Parse(format!("delta output exceeded declared size {result_size}")));
        }
    }
    if output.len() as u64 != result_size {
        return Err(GitError::Parse(format!("delta output {} does not match declared size {result_size}", output.len())));
    }
    Ok((output, instructions))
}
