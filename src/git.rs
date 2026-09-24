use std::io::Read;

use flate2::Decompress;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GitObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl GitObjectType {
    pub fn name(self) -> &'static str {
        match self {
            GitObjectType::Commit => "commit",
            GitObjectType::Tree => "tree",
            GitObjectType::Blob => "blob",
            GitObjectType::Tag => "tag",
            GitObjectType::OfsDelta => "ofs-delta",
            GitObjectType::RefDelta => "ref-delta",
        }
    }

    pub fn is_base(self) -> bool {
        matches!(
            self,
            GitObjectType::Commit | GitObjectType::Tree | GitObjectType::Blob | GitObjectType::Tag
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawPack {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub checksum: String,
    pub stored_checksum: String,
    pub checksum_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackEntry {
    pub index: usize,
    pub object_type: GitObjectType,
    pub header_offset: u64,
    pub type_offset: u64,
    pub data_offset: u64,
    pub compressed_end: Option<u64>,
    pub inflated_size: u64,
    pub inflated_valid: bool,
    pub compressed_len: Option<u64>,
    pub data: Vec<u8>,
    pub negative_offset: Option<u64>,
    pub ref_oid: Option<String>,
    pub crc32: Option<u32>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexFile {
    pub fanout: Vec<u32>,
    pub entries: Vec<IndexEntry>,
    pub pack_checksum: String,
    pub index_checksum: String,
    pub stored_pack_checksum: String,
    pub stored_index_checksum: String,
    pub checksums_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub oid: String,
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LooseObject {
    pub object_type: GitObjectType,
    pub data: Vec<u8>,
    pub declared_size: u64,
    pub data_offset: u64,
    pub compressed_end: Option<u64>,
    pub inflated_valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaInstructions {
    pub source_size: usize,
    pub target_size: usize,
    pub source_size_range: (u64, u64),
    pub target_size_range: (u64, u64),
    pub command_ranges: Vec<CommandRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandRange {
    pub kind: &'static str,
    pub start: u64,
    pub end: u64,
    pub source_start: Option<usize>,
    pub source_len: Option<usize>,
    pub target_len: usize,
}

pub fn be_u32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(data[at..at + 4].try_into().unwrap())
}

pub fn be_u64(data: &[u8], at: usize) -> u64 {
    u64::from_be_bytes(data[at..at + 8].try_into().unwrap())
}

pub fn hex20(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn parse_pack(bytes: &[u8], index_ends: &[u64]) -> Result<RawPack, String> {
    if bytes.len() < 32 {
        return Err("pack smaller than 32 bytes".into());
    }
    if &bytes[0..4] != b"PACK" {
        return Err("missing PACK signature".into());
    }
    let version = be_u32(bytes, 4);
    if version != 2 {
        return Err(format!("unsupported pack version {version}"));
    }
    let count = be_u32(bytes, 8);
    if (bytes.len() as u64) < 12 + count as u64 + 20 {
        return Err("object count exceeds file size".into());
    }
    let stored_checksum = hex::encode(&bytes[bytes.len() - 20..]);
    let checksum = hex::encode(sha1_digest(&bytes[..bytes.len() - 20]));
    let checksum_valid = checksum == stored_checksum;

    let mut entries = Vec::new();
    let mut pos = 12usize;
    for index in 0..count as usize {
        let header_offset = pos as u64;
        let entry = parse_pack_entry(bytes, &mut pos, index, index_ends);
        let recovery = entry.recovery_offset;
        entries.push(entry);
        if pos >= bytes.len().saturating_sub(20) {
            break;
        }
    }
    Ok(RawPack {
        version,
        count,
        entries,
        checksum,
        stored_checksum,
        checksum_valid,
    })
}

fn parse_pack_entry(
    bytes: &[u8],
    pos: &mut usize,
    index: usize,
    index_ends: &[u64],
) -> PackEntry {
    let start = *pos;
    let mut type_code = 0u8;
    let mut size: u64 = 0;
    let mut shift = 0u32;
    for n in 0..10 {
        if *pos >= bytes.len().saturating_sub(20) {
            return entry_error(index, start, *pos, "object header exceeds pack");
        }
        let b = bytes[*pos];
        *pos += 1;
        if n == 0 {
            type_code = (b >> 4) & 7;
            size |= u64::from(b & 0x7f);
            shift = 4;
        } else {
            size |= u64::from(b & 0x7f) << shift;
            shift += 7;
        }
        if b & 0x80 == 0 {
            break;
        }
    }
    let object_type = match type_code {
        1 => GitObjectType::Commit,
        2 => GitObjectType::Tree,
        3 => GitObjectType::Blob,
        4 => GitObjectType::Tag,
        6 => GitObjectType::OfsDelta,
        7 => GitObjectType::RefDelta,
        _ => {
            return entry_error(index, start, *pos, &format!("invalid object type {type_code}"));
        }
    };
    let type_offset = (*pos - 1) as u64;
    let mut negative_offset = None;
    let mut ref_oid = None;
    if object_type == GitObjectType::OfsDelta {
        let mut used = 0usize;
        let value = match read_ofs_delta_offset(bytes, *pos, &mut used) {
            Ok(value) => value,
            Err(error) => return entry_error(index, start, *pos, &error),
        };
        *pos += used;
        negative_offset = Some(value);
    } else if object_type == GitObjectType::RefDelta {
        if *pos + 20 >= bytes.len().saturating_sub(20) {
            return entry_error(index, start, *pos, "ref-delta name exceeds pack");
        }
        ref_oid = Some(hex20(&bytes[*pos..*pos + 20]));
        *pos += 20;
    }
    let data_offset = *pos as u64;
    let expected_end = index_ends
        .iter()
        .find(|&&end| end > data_offset)
        .copied();
    let mut entry = entry_error(index, start, data_offset as usize, "not inflated");
    entry.object_type = object_type;
    entry.type_offset = type_offset;
    entry.data_offset = data_offset;
    entry.inflated_size = size;
    entry.negative_offset = negative_offset;
    entry.ref_oid = ref_oid;

    let (data, end, error) = inflate_pack_object(bytes, *pos, size, expected_end);
    entry.data = data;
    entry.compressed_end = end.map(|value| value as u64);
    entry.recovery_offset = expected_end;
    if entry.parse_error.is_some() {
        if let Some(recovery) = expected_end {
            *pos = recovery as usize;
        }
    }
    entry.compressed_len = end.map(|value| value as u64 - data_offset);
    entry.inflated_valid = error.is_none();
    entry.parse_error = error;
    entry.crc32 = end.map(|end| crc32(&bytes[start..end]));
    if let Some(end) = end {
        *pos = end;
    }
    entry
}

fn entry_error(index: usize, header_offset: usize, data_offset: usize, error: &str) -> PackEntry {
    PackEntry {
        index,
        object_type: GitObjectType::Blob,
        header_offset: header_offset as u64,
        type_offset: header_offset as u64,
        data_offset: data_offset as u64,
        compressed_end: None,
        inflated_size: 0,
        inflated_valid: false,
        compressed_len: None,
        data: Vec::new(),
        negative_offset: None,
        ref_oid: None,
        crc32: None,
        parse_error: Some(error.to_string()),
    }
}

pub fn read_ofs_delta_offset(bytes: &[u8], start: usize, used: &mut usize) -> Result<u64, String> {
    if start >= bytes.len() {
        return Err("missing ofs-delta offset".into());
    }
    let mut value = u64::from(bytes[start] & 0x7f);
    *used = 1;
    let mut pos = start;
    while bytes[pos] & 0x80 != 0 {
        value += 1;
        pos += 1;
        if pos >= bytes.len() {
            return Err("truncated ofs-delta offset".into());
        }
        value = (value << 7) | u64::from(bytes[pos] & 0x7f);
        *used += 1;
    }
    if value > pos as u64 {
        return Err("ofs-delta negative distance points before pack".into());
    }
    Ok(value)
}

pub fn inflate_pack_object(
    bytes: &[u8],
    start: usize,
    declared_size: u64,
    expected_end: Option<u64>,
) -> (Vec<u8>, Option<usize>, Option<String>) {
    let mut decompressor = Decompress::new(true);
    let mut output = Vec::with_capacity(declared_size.min(64 * 1024 * 1024) as usize);
    let mut input_pos = start;
    let mut chunk = [0u8; 8192];
    loop {
        if input_pos >= bytes.len().saturating_sub(20) {
            return (output, None, Some("compressed object reaches pack trailer".into()));
        }
        let available_end = expected_end
            .map(|value| value as usize)
            .unwrap_or_else(|| bytes.len() - 20)
            .min(bytes.len() - 20);
        let input_end = (input_pos + 64 * 1024).min(available_end);
        if input_end <= input_pos {
            return (output, None, Some("compressed object crossed expected boundary".into()));
        }
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let result = decompressor.decompress(
            &bytes[input_pos..input_end],
            &mut chunk,
            flate2::FlushDecompress::None,
        );
        let consumed = (decompressor.total_in() - before_in) as usize;
        let produced = (decompressor.total_out() - before_out) as usize;
        output.extend_from_slice(&chunk[..produced]);
        input_pos += consumed;
        if output.len() > 128 * 1024 * 1024 {
            return (output, None, Some("hard decompression limit exceeded".into()));
        }
        match result {
            Ok(flate2::Status::Ok) => {
                if consumed == 0 && produced == 0 {
                    return (output, None, Some("zlib stream stalled".into()));
                }
            }
            Ok(flate2::Status::BufError) => {}
            Ok(flate2::Status::StreamEnd) => {
                let actual = output.len() as u64;
                let error = if actual != declared_size {
                    Some(format!(
                        "size spoof: header declares {declared_size}, inflate produced {actual}"
                    ))
                } else {
                    None
                };
                return (output, Some(input_pos), error);
            }
            Err(error) => {
                return (
                    output,
                    Some(input_pos),
                    Some(format!("zlib error at byte {}: {error}", input_pos)),
                );
            }
        }
    }
}

pub fn parse_index(bytes: &[u8]) -> Result<IndexFile, String> {
    if bytes.len() < 8 {
        return Err("index smaller than 8 bytes".into());
    }
    let magic = be_u32(bytes, 0);
    let version = be_u32(bytes, 4);
    if magic != 0xff744f63 {
        return Err("only v2 pack indexes are supported".into());
    }
    if version != 2 {
        return Err(format!("unsupported index version {version}"));
    }
    let fanout_start = 8usize;
    let fanout: Vec<u32> = (0..256).map(|i| be_u32(bytes, fanout_start + i * 4)).collect();
    let count = *fanout.last().unwrap();
    let mut previous = 0u32;
    for (bucket, value) in fanout.iter().enumerate() {
        if *value < previous {
            return Err(format!("fanout bucket {bucket} decreases"));
        }
        previous = *value;
    }
    let names_start = fanout_start + 1024;
    let names_end = names_start + count as usize * 20;
    let crc_end = names_end + count as usize * 4;
    let offsets_end = crc_end + count as usize * 4;
    let trailer_len = 40usize;
    if bytes.len() < offsets_end + trailer_len {
        return Err("index truncated before offsets or checksums".into());
    }
    let mut entries = Vec::with_capacity(count as usize);
    let mut last_oid: Option<String> = None;
    for i in 0..count as usize {
        let oid = hex20(&bytes[names_start + i * 20..names_start + (i + 1) * 20]);
        if let Some(last) = &last_oid {
            if &oid <= last {
                return Err("index object names are not strictly sorted".into());
            }
        }
        last_oid = Some(oid.clone());
        let crc32 = be_u32(bytes, names_end + i * 4);
        let raw_offset = be_u32(bytes, crc_end + i * 4);
        let offset = if raw_offset & 0x8000_0000 != 0 {
            let table_index = (raw_offset & 0x7fff_ffff) as usize;
            let table_start = offsets_end;
            let at = table_start + table_index * 8;
            if at + 8 > bytes.len() - 40 {
                return Err("large offset table points outside index".into());
            }
            be_u64(bytes, at)
        } else {
            u64::from(raw_offset)
        };
        entries.push(IndexEntry { oid, offset, crc32 });
    }
    let stored_pack_checksum = hex::encode(&bytes[offsets_end..offsets_end + 20]);
    let stored_index_checksum = hex::encode(&bytes[offsets_end + 20..offsets_end + 40]);
    let pack_checksum = hex::encode(sha1_digest(&bytes[..offsets_end + 20]));
    let index_checksum = hex::encode(sha1_digest(&bytes[..offsets_end + 40]));
    let checksums_valid =
        pack_checksum == stored_pack_checksum && index_checksum == stored_index_checksum;
    Ok(IndexFile {
        fanout,
        entries,
        pack_checksum,
        index_checksum,
        stored_pack_checksum,
        stored_index_checksum,
        checksums_valid,
    })
}

pub fn parse_loose_object(bytes: &[u8]) -> Result<LooseObject, String> {
    let nul = bytes
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(|| "loose object missing NUL header".to_string())?;
    let header = std::str::from_utf8(&bytes[..nul]).map_err(|error| error.to_string())?;
    let (type_name, size_text) = header
        .split_once(' ')
        .ok_or_else(|| "loose object header missing size".to_string())?;
    let object_type = match type_name {
        "commit" => GitObjectType::Commit,
        "tree" => GitObjectType::Tree,
        "blob" => GitObjectType::Blob,
        "tag" => GitObjectType::Tag,
        _ => return Err(format!("unsupported loose object type {type_name}")),
    };
    let declared_size = size_text
        .parse::<u64>()
        .map_err(|error| format!("invalid loose size: {error}"))?;
    let data_offset = nul as u64 + 1;
    let (data, end, parse_error) = inflate_pack_object(
        bytes,
        nul + 1,
        declared_size,
        Some(bytes.len() as u64),
    );
    let mut error = parse_error;
    if let Some(end) = end {
        if end != bytes.len() {
            error = Some(format!(
                "zlib stream ends at {end} but file has {} bytes",
                bytes.len()
            ));
        }
    }
    Ok(LooseObject {
        object_type,
        data,
        declared_size,
        data_offset,
        compressed_end: end.map(|value| value as u64),
        inflated_valid: error.is_none(),
    })
}

pub fn parse_delta_instructions(delta: &[u8]) -> Result<DeltaInstructions, String> {
    let mut pos = 0usize;
    let source_start = pos as u64;
    let source_size = read_delta_size(delta, &mut pos)?;
    let source_size_range = (source_start, pos as u64);
    let target_start = pos as u64;
    let target_size = read_delta_size(delta, &mut pos)?;
    let target_size_range = (target_start, pos as u64);
    let mut command_ranges = Vec::new();
    while pos < delta.len() {
        let start = pos;
        let opcode = delta[pos];
        pos += 1;
        if opcode == 0 {
            return Err("delta opcode 0 is reserved".into());
        }
        if opcode & 0x80 != 0 {
            let mut source_offset = 0usize;
            let mut copy_size = 0usize;
            for bit in 0..7 {
                if opcode & (1 << bit) != 0 {
                    if pos >= delta.len() {
                        return Err("truncated copy instruction".into());
                    }
                    source_offset |= usize::from(delta[pos]) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (bit + 4)) != 0 {
                    if pos >= delta.len() {
                        return Err("truncated copy instruction".into());
                    }
                    copy_size |= usize::from(delta[pos]) << (bit * 8);
                    pos += 1;
                }
            }
            if copy_size == 0 {
                copy_size = 0x10000;
            }
            command_ranges.push(CommandRange {
                kind: "copy",
                start: start as u64,
                end: pos as u64,
                source_start: Some(source_offset),
                source_len: Some(copy_size),
                target_len: copy_size,
            });
        } else {
            let length = opcode as usize;
            if pos + length > delta.len() {
                return Err("insert instruction runs past delta".into());
            }
            pos += length;
            command_ranges.push(CommandRange {
                kind: "insert",
                start: start as u64,
                end: pos as u64,
                source_start: None,
                source_len: None,
                target_len: length,
            });
        }
    }
    let produced: usize = command_ranges.iter().map(|range| range.target_len).sum();
    if produced != target_size {
        return Err(format!(
            "delta target size {target_size} disagrees with instructions producing {produced}"
        ));
    }
    Ok(DeltaInstructions {
        source_size,
        target_size,
        source_size_range,
        target_size_range,
        command_ranges,
    })
}

fn read_delta_size(bytes: &[u8], pos: &mut usize) -> Result<usize, String> {
    let mut value = 0usize;
    let mut shift = 0u32;
    loop {
        if *pos >= bytes.len() {
            return Err("delta variable size truncated".into());
        }
        let b = bytes[*pos];
        *pos += 1;
        value |= usize::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift > 56 {
            return Err("delta size too large".into());
        }
    }
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<(Vec<u8>, DeltaInstructions), String> {
    let instructions = parse_delta_instructions(delta)?;
    if base.len() != instructions.source_size {
        return Err(format!(
            "delta source size {} does not match base length {}",
            instructions.source_size,
            base.len()
        ));
    }
    let mut output = Vec::with_capacity(instructions.target_size.min(64 * 1024 * 1024));
    let mut delta_pos = positions_after_sizes(delta)?;
    while delta_pos < delta.len() {
        let opcode = delta[delta_pos];
        delta_pos += 1;
        if opcode & 0x80 != 0 {
            let mut source_offset = 0usize;
            let mut copy_size = 0usize;
            for bit in 0..7 {
                if opcode & (1 << bit) != 0 {
                    source_offset |= usize::from(delta[delta_pos]) << (bit * 8);
                    delta_pos += 1;
                }
            }
            for bit in 0..3 {
                if opcode & (1 << (bit + 4)) != 0 {
                    copy_size |= usize::from(delta[delta_pos]) << (bit * 8);
                    delta_pos += 1;
                }
            }
            if copy_size == 0 {
                copy_size = 0x10000;
            }
            let end = source_offset
                .checked_add(copy_size)
                .ok_or_else(|| "copy range overflow".to_string())?;
            if end > base.len() {
                return Err(format!(
                    "copy range {source_offset}..{end} exceeds base length {}",
                    base.len()
                ));
            }
            output.extend_from_slice(&base[source_offset..end]);
        } else {
            let length = opcode as usize;
            if delta_pos + length > delta.len() {
                return Err("insert range exceeds delta".into());
            }
            output.extend_from_slice(&delta[delta_pos..delta_pos + length]);
            delta_pos += length;
        }
        if output.len() > instructions.target_size {
            return Err("instructions overran declared target size".into());
        }
    }
    if output.len() != instructions.target_size {
        return Err(format!(
            "output length {} differs from declared target {}",
            output.len(),
            instructions.target_size
        ));
    }
    Ok((output, instructions))
}

fn positions_after_sizes(delta: &[u8]) -> Result<usize, String> {
    let mut pos = 0usize;
    read_delta_size(delta, &mut pos)?;
    read_delta_size(delta, &mut pos)?;
    Ok(pos)
}

pub fn git_object_id(object_type: GitObjectType, data: &[u8]) -> String {
    use sha1::{Digest, Sha1};
    use std::io::Write;
    let header = format!("{} {}\0", object_type.name(), data.len());
    let mut hasher = Sha1::new();
    hasher.update(header.as_bytes());
    hasher.update(data);
    let id: [u8; 20] = hasher.finalize().into();
    hex::encode(id)
}

pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn content_digest(data: &[u8]) -> String {
    sha256_hex(data)
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

pub fn preview_text(data: &[u8], max: usize) -> String {
    let sample = &data[..data.len().min(max)];
    let text: String = sample
        .iter()
        .map(|byte| {
            if (0x20..=0x7e).contains(byte) || *byte == b'\n' || *byte == b'\t' || *byte == b'\r' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect();
    if data.len() > max {
        format!("{text}…")
    } else {
        text
    }
}
