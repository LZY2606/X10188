use crc32fast::Hasher as CrcHasher;
use flate2::{Decompress, FlushDecompress, Status};
use serde::Serialize;
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::fmt;

pub const MAX_RAW_DECOMPRESSED: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjectType {
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Commit),
            2 => Some(Self::Tree),
            3 => Some(Self::Blob),
            4 => Some(Self::Tag),
            6 => Some(Self::OfsDelta),
            7 => Some(Self::RefDelta),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
            Self::OfsDelta => "ofs-delta",
            Self::RefDelta => "ref-delta",
        }
    }

    pub fn is_base(self) -> bool {
        matches!(self, Self::Commit | Self::Tree | Self::Blob | Self::Tag)
    }
}

impl fmt::Display for ObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum DeltaBaseRef {
    Offset(u64),
    Oid(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct Evidence {
    pub code: String,
    pub offset: Option<u64>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DeltaOpKind {
    Insert,
    Copy,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaOpRange {
    pub kind: DeltaOpKind,
    pub instruction_start: u64,
    pub instruction_end: u64,
    pub source_start: u64,
    pub length: u64,
    pub target_start: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeltaInstructionSet {
    pub base_size: u64,
    pub result_size: u64,
    pub instructions_offset: u64,
    pub operations: Vec<DeltaOpRange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackEntry {
    pub sequence: usize,
    pub offset: u64,
    pub data_offset: u64,
    pub zlib_end: Option<u64>,
    pub next_offset: u64,
    pub type_code: u8,
    pub object_type: Option<ObjectType>,
    pub declared_size: u64,
    pub actual_decompressed_size: Option<u64>,
    pub delta_base: Option<DeltaBaseRef>,
    pub payload: Vec<u8>,
    pub delta: Option<DeltaInstructionSet>,
    pub expected_oid: Option<String>,
    pub crc32: Option<u32>,
    pub crc_valid: Option<bool>,
    pub error: Option<String>,
}

impl PackEntry {
    pub fn is_usable(&self) -> bool {
        self.object_type.is_some() && self.error.is_none() && self.zlib_end.is_some()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexMapping {
    pub oid: String,
    pub offset: u64,
    pub crc32: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexReport {
    pub version: u32,
    pub object_count: u64,
    pub fanout: Vec<u32>,
    pub fanout_valid: bool,
    pub mappings: Vec<IndexMapping>,
    pub errors: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackReport {
    pub version: u32,
    pub object_count: u32,
    pub entries: Vec<PackEntry>,
    pub checksum_expected: String,
    pub checksum_actual: String,
    pub checksum_valid: bool,
    pub index: Option<IndexReport>,
    pub errors: Vec<Evidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LooseObject {
    pub expected_oid: Option<String>,
    pub actual_oid: String,
    pub object_type: ObjectType,
    pub payload: Vec<u8>,
    pub data_offset: u64,
    pub zlib_end: u64,
    pub error: Option<String>,
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn git_object_id(object_type: ObjectType, payload: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("{} {}\0", object_type, payload.len()).as_bytes());
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

fn read_size_encoding(data: &[u8], mut offset: usize) -> Result<(u8, u64, usize), String> {
    let first = *data.get(offset).ok_or_else(|| "object header truncated".to_string())?;
    let kind = (first >> 4) & 0x07;
    let mut size = u64::from(first & 0x7f);
    let mut shift = 4;
    offset += 1;
    let mut current = first;
    while current & 0x80 != 0 {
        current = *data
            .get(offset)
            .ok_or_else(|| "object size continuation truncated".to_string())?;
        offset += 1;
        let part = u64::from(current & 0x7f);
        if shift >= 64 || part.checked_shl(shift).is_none() {
            return Err("object size overflow".to_string());
        }
        size |= part << shift;
        shift += 7;
    }
    Ok((kind, size, offset))
}

fn read_ofs_distance(data: &[u8], mut offset: usize) -> Result<(u64, usize), String> {
    let mut byte = *data
        .get(offset)
        .ok_or_else(|| "ofs-delta distance truncated".to_string())?;
    offset += 1;
    let mut distance = u64::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        byte = *data
            .get(offset)
            .ok_or_else(|| "ofs-delta distance continuation truncated".to_string())?;
        offset += 1;
        distance = distance
            .checked_add(1)
            .and_then(|value| value.checked_shl(7))
            .and_then(|value| value | u64::from(byte & 0x7f).into())
            .ok_or_else(|| "ofs-delta distance overflow".to_string())?;
    }
    Ok((distance, offset))
}

fn decompress_zlib(input: &[u8], declared_size: u64) -> Result<(Vec<u8>, usize), String> {
    let mut decompressor = Decompress::new(true);
    let mut output = Vec::new();
    let mut input_consumed = 0usize;
    loop {
        let mut chunk = [0u8; 16 * 1024];
        let before_in = decompressor.total_in() as usize;
        let before_out = decompressor.total_out() as usize;
        let status = decompressor.in_slice(
            &input[input_consumed..],
            &mut chunk,
            FlushDecompress::None,
        );
        input_consumed = before_in + decompressor.total_in() as usize - before_in;
        let produced = decompressor.total_out() as usize - before_out;
        output.extend_from_slice(&chunk[..produced]);
        if decompressor.total_out() > MAX_RAW_DECOMPRESSED {
            return Err(format!(
                "decompressed object exceeds safety cap of {MAX_RAW_DECOMPRESSED} bytes"
            ));
        }
        match status {
            Ok(Status::StreamEnd) => break,
            Ok(Status::Ok | Status::BufError) => {
                if input_consumed == input.len() && produced == 0 {
                    return Err("zlib stream ended before object data".to_string());
                }
            }
            Err(error) => return Err(format!("zlib decompression failed: {error}")),
        }
    }
    if output.len() as u64 != declared_size {
        return Err(format!(
            "size spoof: header declared {declared_size} bytes but zlib stream produced {} bytes",
            output.len()
        ));
    }
    Ok((output, input_consumed))
}

pub fn parse_delta(data: &[u8]) -> Result<DeltaInstructionSet, String> {
    let mut cursor = Reader::new(data);
    let base_size = cursor.varint()?;
    let result_size = cursor.varint()?;
    let instructions_offset = cursor.position() as u64;
    let mut operations = Vec::new();
    let mut target_offset = 0u64;
    while cursor.remaining() > 0 {
        let instruction_start = cursor.position() as u64;
        let opcode = cursor.byte()?;
        if opcode == 0 {
            return Err("delta opcode 0 is reserved".to_string());
        }
        if opcode & 0x80 != 0 {
            let mut copy_offset = 0u32;
            let mut copy_size = 0u32;
            for bit in 0..4u8 {
                if opcode & (1 << bit) != 0 {
                    copy_offset |= u32::from(cursor.byte()?) << (8 * bit);
                }
            }
            for bit in 0..3u8 {
                if opcode & (1 << (4 + bit)) != 0 {
                    copy_size |= u32::from(cursor.byte()?) << (8 * bit);
                }
            }
            if copy_size == 0 {
                copy_size = 0x10000;
            }
            let end = copy_offset
                .checked_add(copy_size)
                .ok_or_else(|| "copy range overflow".to_string())?;
            if u64::from(end) > base_size {
                return Err("copy range reads outside base object".to_string());
            }
            let length = u64::from(copy_size);
            operations.push(DeltaOpRange {
                kind: DeltaOpKind::Copy,
                instruction_start,
                instruction_end: cursor.position() as u64,
                source_start: u64::from(copy_offset),
                length,
                target_start: target_offset,
                bytes: Vec::new(),
            });
            target_offset = target_offset
                .checked_add(length)
                .ok_or_else(|| "target offset overflow".to_string())?;
        } else {
            let length = u64::from(opcode);
            if cursor.remaining() as u64 < length {
                return Err("insert instruction runs outside delta stream".to_string());
            }
            operations.push(DeltaOpRange {
                kind: DeltaOpKind::Insert,
                instruction_start,
                instruction_end: cursor.position() as u64 + length,
                source_start: cursor.position() as u64,
                length,
                target_start: target_offset,
                bytes: data[cursor.position()..cursor.position() + length].to_vec(),
            });
            cursor.skip(length as usize)?;
            target_offset = target_offset
                .checked_add(length)
                .ok_or_else(|| "target offset overflow".to_string())?;
        }
        if target_offset > result_size {
            return Err("delta instructions write past declared result size".to_string());
        }
    }
    if target_offset != result_size {
        return Err(format!(
            "delta result size spoof: header declared {result_size} bytes but instructions produce {target_offset} bytes"
        ));
    }
    Ok(DeltaInstructionSet {
        base_size,
        result_size,
        instructions_offset,
        operations,
    })
}

pub fn apply_delta(base: &[u8], instructions: &DeltaInstructionSet) -> Result<Vec<u8>, String> {
    if base.len() as u64 != instructions.base_size {
        return Err(format!(
            "base length {} does not match delta base size {}",
            base.len(),
            instructions.base_size
        ));
    }
    let mut result = Vec::with_capacity(instructions.result_size as usize);
    for op in &instructions.operations {
        let start = op.source_start as usize;
        let length = op.length as usize;
        match op.kind {
            DeltaOpKind::Insert => result.extend_from_slice(&op.bytes),
            DeltaOpKind::Copy => {
                result.extend_from_slice(
                    base.get(start..start + length)
                        .ok_or_else(|| "copy range outside base".to_string())?,
                );
            }
        }
    }
    Ok(result)
}

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn position(&self) -> usize {
        self.position
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.position)
    }

    fn byte(&mut self) -> Result<u8, String> {
        let value = self
            .data
            .get(self.position)
            .copied()
            .ok_or_else(|| "unexpected end of delta".to_string())?;
        self.position += 1;
        Ok(value)
    }

    fn skip(&mut self, amount: usize) -> Result<(), String> {
        if self.position.checked_add(amount).ok_or("offset overflow")? > self.data.len() {
            return Err("skip outside delta".to_string());
        }
        self.position += amount;
        Ok(())
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut shift = 0u32;
        let mut value = 0u64;
        loop {
            let byte = self.byte()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err("delta varint overflow".to_string());
            }
        }
        Ok(value)
    }
}
