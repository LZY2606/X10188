use crate::git::{crc32, inflate_declared, read_size_encoding, GitError, ObjectType};
use sha1::{Digest, Sha1};

#[derive(Clone, Debug)]
pub struct PackHeader {
    pub version: u32,
    pub object_count: u32,
    pub header_offset: usize,
}

#[derive(Clone, Debug)]
pub struct PackObject {
    pub index: usize,
    pub offset: usize,
    pub header_end: usize,
    pub data_start: usize,
    pub data_end: usize,
    pub next_offset: usize,
    pub kind: ObjectType,
    pub declared_size: usize,
    pub payload: Vec<u8>,
    pub crc32: u32,
    pub ofs_base: Option<i64>,
    pub ref_base: Option<[u8; 20]>,
    pub parse_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct PackEvidence {
    pub actual_trailer: [u8; 20],
    pub computed_sha1: [u8; 20],
    pub checksum_valid: bool,
}

#[derive(Debug)]
pub struct ParsedPack {
    pub header: PackHeader,
    pub objects: Vec<PackObject>,
    pub evidence: PackEvidence,
    pub object_errors: Vec<PackObjectError>,
    pub raw_len: usize,
}

#[derive(Clone, Debug)]
pub struct PackObjectError {
    pub offset: usize,
    pub end: Option<usize>,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct IndexEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc32: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct ParsedIndex {
    pub version: u32,
    pub fanout: Vec<u32>,
    pub entries: Vec<IndexEntry>,
    pub pack_checksum: [u8; 20],
    pub index_checksum: [u8; 20],
    pub computed_pack_sha1: Option<[u8; 20]>,
    pub checksum_valid: bool,
}

fn u32_at(data: &[u8], pos: usize) -> Result<u32, GitError> {
    data.get(pos..pos + 4)
        .and_then(|slice| slice.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(GitError::Truncated("u32"))
}

fn sha1_at(data: &[u8], pos: usize) -> Result<[u8; 20], GitError> {
    data.get(pos..pos + 20)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(GitError::Truncated("sha1"))
}

pub fn parse_pack(data: &[u8]) -> Result<ParsedPack, GitError> {
    if data.len() < 32 || &data[..4] != b"PACK" {
        return Err(GitError::BadHeader("missing PACK magic".into()));
    }
    let version = u32_at(data, 4)?;
    if version != 2 {
        return Err(GitError::Unsupported(format!("pack version {version}")));
    }
    let object_count = u32_at(data, 8)?;
    let trailer_pos = data
        .len()
        .checked_sub(20)
        .ok_or(GitError::Truncated("pack trailer"))?;
    let mut computed_hasher = Sha1::new();
    computed_hasher.update(&data[..trailer_pos]);
    let computed_sha1: [u8; 20] = computed_hasher.finalize().into();
    let actual_trailer = sha1_at(data, trailer_pos)?;

    let mut objects = Vec::new();
    let mut object_errors = Vec::new();
    let mut pos = 12;
    for index in 0..object_count as usize {
        let offset = pos;
        if offset >= trailer_pos {
            object_errors.push(PackObjectError {
                offset,
                end: None,
                message: GitError::Truncated("object header").to_string(),
            });
            break;
        }
        match parse_pack_object(data, pos, trailer_pos, index) {
            Ok(object) => {
                pos = object.next_offset;
                objects.push(object);
            }
            Err(err) => {
                object_errors.push(PackObjectError {
                    offset,
                    end: None,
                    message: err.to_string(),
                });
                break;
            }
        }
    }
    if objects.len() != object_count as usize && object_errors.is_empty() {
        object_errors.push(PackObjectError {
            offset: pos,
            end: None,
            message: format!(
                "declared {} objects but parsed {}",
                object_count,
                objects.len()
            ),
        });
    }
    if let Some(last) = objects.last() {
        if last.next_offset != trailer_pos {
            object_errors.push(PackObjectError {
                offset: last.next_offset,
                end: Some(trailer_pos),
                message: format!(
                    "zlib object layout ends at {}, pack body ends at {trailer_pos}",
                    last.next_offset
                ),
            });
        }
    }
    Ok(ParsedPack {
        header: PackHeader {
            version,
            object_count,
            header_offset: 0,
        },
        objects,
        evidence: PackEvidence {
            actual_trailer,
            computed_sha1,
            checksum_valid: actual_trailer == computed_sha1,
        },
        object_errors,
        raw_len: data.len(),
    })
}

fn parse_pack_object(
    data: &[u8],
    start: usize,
    end: usize,
    index: usize,
) -> Result<PackObject, GitError> {
    let mut pos = start;
    let first = *data.get(pos).ok_or(GitError::Truncated("object byte"))?;
    pos += 1;
    let type_number = (first >> 4) & 0b111;
    let kind = match type_number {
        1 => ObjectType::Commit,
        2 => ObjectType::Tree,
        3 => ObjectType::Blob,
        4 => ObjectType::Tag,
        6 => ObjectType::OfsDelta,
        7 => ObjectType::RefDelta,
        other => return Err(GitError::BadHeader(format!("object type {other}"))),
    };
    let mut declared_size = (first & 0x7f) as usize;
    let mut shift = 7u32;
    let mut current = first;
    while current & 0x80 != 0 {
        let byte = *data.get(pos).ok_or(GitError::Truncated("size byte"))?;
        pos += 1;
        declared_size |= ((byte & 0x7f) as usize)
            .checked_shl(shift)
            .ok_or_else(|| GitError::BadHeader("object size overflow".into()))?;
        shift += 7;
        current = byte;
    }
    let mut ofs_base = None;
    let mut ref_base = None;
    if kind == ObjectType::OfsDelta {
        let mut byte = *data.get(pos).ok_or(GitError::Truncated("ofs byte"))?;
        pos += 1;
        let mut distance = (byte & 0x7f) as i64;
        while byte & 0x80 != 0 {
            byte = *data.get(pos).ok_or(GitError::Truncated("ofs byte"))?;
            pos += 1;
            distance = ((distance + 1) << 7) | (byte & 0x7f) as i64;
        }
        let base_offset = start as i64 - distance;
        if base_offset < 12 || base_offset >= start as i64 {
            return Err(GitError::BadDelta(format!(
                "ofs-delta distance {distance} points outside pack"
            )));
        }
        ofs_base = Some(base_offset);
    }
    if kind == ObjectType::RefDelta {
        ref_base = Some(sha1_at(data, pos)?);
        pos += 20;
    }
    let header_end = pos;
    if header_started_after_body(header_end, end) {
        return Err(GitError::Truncated("compressed object"));
    }
    let stream = inflate_at(data, header_end)?;
    let data_start = header_end;
    let data_end = header_end + stream.consumed;
    if data_end > end {
        return Err(GitError::BadZlib("stream crosses pack body boundary".into()));
    }
    let parse_error = if stream.data.len() != declared_size {
        Some(GitError::SizeMismatch {
            declared: declared_size,
            actual: stream.data.len(),
        }.to_string())
    } else {
        None
    };
    Ok(PackObject {
        index,
        offset: start,
        header_end,
        data_start,
        data_end,
        next_offset: data_end,
        kind,
        declared_size,
        payload: stream.data,
        crc32: crc32(&data[start..data_end]),
        ofs_base,
        ref_base,
        parse_error,
    })
}

fn header_started_after_body(header_end: usize, body_end: usize) -> bool {
    header_end > body_end
}

pub fn parse_index(data: &[u8], pack: Option<&[u8]>) -> Result<ParsedIndex, GitError> {
    if data.len() < 1032 {
        return Err(GitError::Truncated("index"));
    }
    let (version, fanout_pos, is_v2) = if &data[..4] == b"\xfftOc" {
        let version = u32_at(data, 4)?;
        if version != 2 {
            return Err(GitError::Unsupported(format!("index version {version}")));
        }
        (version, 8, true)
    } else {
        (1, 0, false)
    };
    let mut fanout = Vec::with_capacity(256);
    for bucket in 0..256 {
        fanout.push(u32_at(data, fanout_pos + bucket * 4)?);
    }
    let count = *fanout.last().unwrap() as usize;
    let mut pos = if is_v2 { fanout_pos + 1024 } else { 1024 };
    if is_v2 {
        let mut oids = Vec::with_capacity(count);
        for _ in 0..count {
            oids.push(sha1_at(data, pos)?);
            pos += 20;
        }
        let mut crcs = Vec::with_capacity(count);
        for _ in 0..count {
            crcs.push(Some(u32_at(data, pos)?));
            pos += 4;
        }
        let mut offsets = Vec::with_capacity(count);
        for _ in 0..count {
            let raw = u32_at(data, pos)?;
            pos += 4;
            if raw & 0x80000000 != 0 {
                return Err(GitError::Unsupported("64-bit large pack offsets".into()));
            }
            offsets.push(raw as u64);
        }
        let pack_checksum = sha1_at(data, pos)?;
        let index_checksum = sha1_at(data, pos + 20)?;
        let computed_pack_sha1 = pack.map(|pack_data| {
            let mut hasher = Sha1::new();
            hasher.update(&pack_data[..pack_data.len() - 20]);
            hasher.finalize().into()
        });
        let entries = oids
            .into_iter()
            .zip(crccs)
            .zip(offsets)
            .map(|((oid, crc), offset)| IndexEntry {
                oid,
                offset,
                crc32: crc,
            })
            .collect();
        return Ok(ParsedIndex {
            version,
            fanout,
            entries,
            pack_checksum,
            index_checksum,
            computed_pack_sha1,
            checksum_valid: computed_pack_sha1
                .map(|sum| sum == pack_checksum)
                .unwrap_or(true),
        });
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let offset = u32_at(data, pos)?;
        pos += 4;
        let oid = sha1_at(data, pos)?;
        pos += 20;
        entries.push(IndexEntry {
            oid,
            offset: offset as u64,
            crc32: None,
        });
    }
    let pack_checksum = sha1_at(data, pos)?;
    let index_checksum = sha1_at(data, pos + 20)?;
    let computed_pack_sha1 = pack.map(|pack_data| {
        let mut hasher = Sha1::new();
        hasher.update(&pack_data[..pack_data.len() - 20]);
        hasher.finalize().into()
    });
    Ok(ParsedIndex {
        version,
        fanout,
        entries,
        pack_checksum,
        index_checksum,
        computed_pack_sha1,
        checksum_valid: computed_pack_sha1
            .map(|sum| sum == pack_checksum)
            .unwrap_or(true),
    })
}
