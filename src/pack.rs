//! Pure, Git-free parser for `PACK` v2 container files.

use crate::gitobj::ptype;
use crate::leb128::{read_ofs_distance, read_pack_size};
use crate::zstream::{inflate_from, InflateError};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: usize,
    pub obj_type: u8,
    /// Header-declared uncompressed size.
    pub declared_size: u64,
    /// For ofs-delta: absolute base offset inside this pack.
    pub base_offset: Option<usize>,
    /// For ref-delta: claimed base oid (20 bytes).
    pub base_oid: Option<[u8; 20]>,
    /// Offset at which the zlib stream starts.
    pub z_start: usize,
    /// Bytes consumed by the zlib stream (None on truncated/error streams).
    pub z_consumed: Option<usize>,
    /// Inflated bytes (delta payload or full object). None on failure.
    pub payload: Option<Vec<u8>>,
    pub inflate_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackWarning {
    pub offset: Option<usize>,
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub version: u32,
    pub num_objects: u32,
    pub entries: Vec<PackEntry>,
    pub warnings: Vec<PackWarning>,
    /// SHA-1 over the first (len-20) bytes.
    pub computed_checksum: [u8; 20],
    pub stored_checksum: [u8; 20],
    pub checksum_ok: bool,
    pub file_len: usize,
}

pub const PACK_MAGIC: [u8; 4] = *b"PACK";

#[derive(Debug)]
pub struct PackFatal(pub String);

impl std::fmt::Display for PackFatal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pack: {}", self.0)
    }
}
impl std::error::Error for PackFatal {}

pub fn parse_pack(data: &[u8], max_object_bytes: u64) -> Result<ParsedPack, PackFatal> {
    if data.len() < 32 {
        return Err(PackFatal("file shorter than 32 bytes".into()));
    }
    if &data[..4] != &PACK_MAGIC {
        return Err(PackFatal("missing PACK magic".into()));
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(PackFatal(format!("unsupported pack version {}", version)));
    }
    let num_objects = u32::from_be_bytes(data[8..12].try_into().unwrap());

    let mut entries = Vec::new();
    let mut warnings = Vec::new();
    let mut pos = 12usize;
    // The last 20 bytes are the checksum; zlib streams never touch them.
    let body_end = data.len() - 20;

    for idx in 0..num_objects {
        if pos >= body_end {
            warnings.push(PackWarning {
                offset: Some(pos),
                code: "truncated_header".into(),
                message: format!("object {} header starts beyond pack body", idx),
            });
            break;
        }
        let entry_offset = pos;
        let first = data[pos];
        pos += 1;
        let obj_type = (first >> 4) & 0b111;
        let declared = read_pack_size(first, data, &mut pos)
            .map_err(|e| PackFatal(format!("object {} at {}: {}", idx, entry_offset, e)))?;

        let mut base_offset = None;
        let mut base_oid = None;
        match obj_type {
            ptype::OFS_DELTA => {
                let dist = read_ofs_distance(data, &mut pos)
                    .map_err(|e| PackFatal(format!("ofs-delta at {}: {}", entry_offset, e)))?;
                if dist as usize > pos {
                    warnings.push(PackWarning {
                        offset: Some(entry_offset),
                        code: "ofs_out_of_bounds".into(),
                        message: format!(
                            "negative offset distance {} at {} runs before pack header",
                            dist, entry_offset
                        ),
                    });
                } else {
                    base_offset = Some(pos - dist as usize);
                }
            }
            ptype::REF_DELTA => {
                if pos + 20 > body_end {
                    return Err(PackFatal(format!(
                        "ref-delta at {} truncated base oid",
                        entry_offset
                    )));
                }
                let mut oid = [0u8; 20];
                oid.copy_from_slice(&data[pos..pos + 20]);
                pos += 20;
                base_oid = Some(oid);
            }
            ptype::COMMIT | ptype::TREE | ptype::BLOB | ptype::TAG => {}
            other => {
                warnings.push(PackWarning {
                    offset: Some(entry_offset),
                    code: "unknown_type".into(),
                    message: format!("unknown type {} at offset {}", other, entry_offset),
                });
            }
        }

        let z_start = pos;
        let outcome = inflate_from(data, z_start, Some(declared), max_object_bytes);
        let entry = match outcome {
            Ok(oc) => {
                let end = z_start + oc.input_consumed;
                pos = end;
                PackEntry {
                    offset: entry_offset,
                    obj_type,
                    declared_size: declared,
                    base_offset,
                    base_oid,
                    z_start,
                    z_consumed: Some(oc.input_consumed),
                    payload: Some(oc.data),
                    inflate_error: None,
                }
            }
            Err(InflateError {
                message,
                partial,
                input_consumed,
            }) => {
                warnings.push(PackWarning {
                    offset: Some(entry_offset),
                    code: "inflate_failed".into(),
                    message: message.clone(),
                });
                // Try to recover scanning position: for a corrupted stream we
                // cannot reliably find the next entry; stop parsing further
                // entries but keep everything seen so far.
                let end = z_start + input_consumed;
                let _ = partial;
                entries.push(PackEntry {
                    offset: entry_offset,
                    obj_type,
                    declared_size: declared,
                    base_offset,
                    base_oid,
                    z_start,
                    z_consumed: None,
                    payload: None,
                    inflate_error: Some(message),
                });
                let _ = end;
                break;
            }
        };
        entries.push(entry);
    }

    if entries.len() as u32 != num_objects {
        warnings.push(PackWarning {
            offset: None,
            code: "object_count_mismatch".into(),
            message: format!(
                "header declares {} objects, {} parsed",
                num_objects,
                entries.len()
            ),
        });
    }

    let mut hasher = Sha1::new();
    hasher.update(&data[..body_end]);
    let mut computed = [0u8; 20];
    computed.copy_from_slice(&hasher.finalize());
    let mut stored = [0u8; 20];
    stored.copy_from_slice(&data[body_end..body_end + 20]);

    Ok(ParsedPack {
        version,
        num_objects,
        entries,
        warnings,
        computed_checksum: computed,
        stored_checksum: stored,
        checksum_ok: computed == stored,
        file_len: data.len(),
    })
}
