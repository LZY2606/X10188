//! Git pack (.pack) and pack index (.idx v2) parsing.
//! No external git tooling is used; everything is parsed byte by byte.

use crate::gitobj::{sha1_hex, zlib_decompress_bounded, ObjType};

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Offset of the entry header inside the pack file.
    pub offset: u64,
    pub obj_type: ObjType,
    /// Size declared in the entry header (uncompressed size for base
    /// objects, delta-result size for delta objects).
    pub declared_size: u64,
    /// Offset where the zlib stream starts.
    pub data_offset: u64,
    /// Compressed length of the zlib stream (exact boundary).
    pub data_len: u64,
    /// For ofs-delta: the negative distance encoded in the entry.
    pub ofs_distance: Option<u64>,
    /// For ref-delta: the base object id (hex).
    pub ref_base: Option<String>,
    /// CRC-32 over the raw entry bytes (header + base ref + zlib data).
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub version: u32,
    pub object_count: u32,
    pub entries: Vec<PackEntry>,
    /// SHA-1 recorded in the pack trailer.
    pub trailer_sha1: String,
    /// Whether the trailer matches the recomputed hash of the pack body.
    pub trailer_ok: bool,
}

#[derive(Debug, Clone)]
pub struct PackError {
    pub offset: u64,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PackParse {
    pub pack: Option<PackFile>,
    pub errors: Vec<PackError>,
}

/// Parse a pack file. Parsing is resilient: a corrupt entry is recorded as
/// an error and parsing stops for the remainder of that pack (offsets of
/// later entries cannot be trusted), but everything parsed so far is kept.
pub fn parse_pack(data: &[u8]) -> Result<PackParse, String> {
    let mut errors = Vec::new();
    if data.len() < 12 + 20 {
        return Err(format!("pack too small: {} bytes", data.len()));
    }
    if &data[0..4] != b"PACK" {
        return Err("missing PACK signature".to_string());
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        return Err(format!("unsupported pack version {version}"));
    }
    let object_count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let body_end = data.len() - 20;
    let trailer_sha1 = hex::encode(&data[body_end..]);
    let trailer_ok = sha1_hex(&data[..body_end]) == trailer_sha1;

    let mut entries = Vec::new();
    let mut pos = 12usize;
    for _ in 0..object_count {
        if pos >= body_end {
            errors.push(PackError {
                offset: pos as u64,
                message: format!(
                    "pack ended early: expected {object_count} objects, parsed {}",
                    entries.len()
                ),
            });
            break;
        }
        let entry_offset = pos;
        // Type + size varint header.
        let mut c = data[pos];
        pos += 1;
        let type_code = (c >> 4) & 0x7;
        let obj_type = match ObjType::from_pack_code(type_code) {
            Some(t) => t,
            None => {
                errors.push(PackError {
                    offset: entry_offset as u64,
                    message: format!("unknown object type code {type_code}"),
                });
                break;
            }
        };
        let mut size = (c & 0x0f) as u64;
        let mut shift = 4u32;
        while c & 0x80 != 0 {
            if pos >= body_end {
                errors.push(PackError {
                    offset: entry_offset as u64,
                    message: "truncated size varint".into(),
                });
                break;
            }
            c = data[pos];
            pos += 1;
            size |= ((c & 0x7f) as u64) << shift;
            shift += 7;
        }
        // Delta base reference.
        let mut ofs_distance = None;
        let mut ref_base = None;
        match obj_type {
            ObjType::OfsDelta => {
                if pos >= body_end {
                    errors.push(PackError {
                        offset: entry_offset as u64,
                        message: "truncated ofs-delta base offset".into(),
                    });
                    break;
                }
                let mut b = data[pos];
                pos += 1;
                let mut dist = (b & 0x7f) as u64;
                while b & 0x80 != 0 {
                    if pos >= body_end {
                        errors.push(PackError {
                            offset: entry_offset as u64,
                            message: "truncated ofs-delta base offset".into(),
                        });
                        break;
                    }
                    b = data[pos];
                    pos += 1;
                    dist = ((dist + 1) << 7) | (b & 0x7f) as u64;
                }
                ofs_distance = Some(dist);
            }
            ObjType::RefDelta => {
                if pos + 20 > body_end {
                    errors.push(PackError {
                        offset: entry_offset as u64,
                        message: "truncated ref-delta base oid".into(),
                    });
                    break;
                }
                ref_base = Some(hex::encode(&data[pos..pos + 20]));
                pos += 20;
            }
            _ => {}
        }
        // Zlib stream with exact boundary detection.
        let data_offset = pos;
        let (raw, used) = match zlib_decompress_bounded(&data[pos..body_end]) {
            Ok(v) => v,
            Err(e) => {
                errors.push(PackError {
                    offset: entry_offset as u64,
                    message: format!("zlib boundary failure: {e}"),
                });
                break;
            }
        };
        let _ = raw; // content is re-decompressed lazily by the engine
        pos += used;
        let crc32 = crc32fast::hash(&data[entry_offset..pos]);
        entries.push(PackEntry {
            offset: entry_offset as u64,
            obj_type,
            declared_size: size,
            data_offset: data_offset as u64,
            data_len: used as u64,
            ofs_distance,
            ref_base,
            crc32,
        });
    }
    Ok(PackParse {
        pack: Some(PackFile {
            version,
            object_count,
            entries,
            trailer_sha1,
            trailer_ok,
        }),
        errors,
    })
}

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct IdxFile {
    pub version: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: String,
    pub idx_sha1: String,
    pub idx_sha1_ok: bool,
}

/// Parse a v2 pack index. V1 indexes are reported as unsupported.
pub fn parse_idx(data: &[u8]) -> Result<IdxFile, String> {
    if data.len() < 8 {
        return Err("idx too small".into());
    }
    if data[0..4] == [0xff, 0x74, 0x4f, 0x63] {
        let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if version != 2 {
            return Err(format!("unsupported idx version {version}"));
        }
        let mut pos = 8usize;
        let mut fanout = [0u32; 256];
        for f in fanout.iter_mut() {
            *f = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
        }
        let n = fanout[255] as usize;
        let need = pos + n * 20 + n * 4 + n * 4 + 40;
        if data.len() < need {
            return Err(format!(
                "idx truncated: need at least {need} bytes, have {}",
                data.len()
            ));
        }
        let mut oids = Vec::with_capacity(n);
        for _ in 0..n {
            oids.push(hex::encode(&data[pos..pos + 20]));
            pos += 20;
        }
        let mut crcs = Vec::with_capacity(n);
        for _ in 0..n {
            crcs.push(u32::from_be_bytes([
                data[pos],
                data[pos + 1],
                data[pos + 2],
                data[pos + 3],
            ]));
            pos += 4;
        }
        let mut offs = Vec::with_capacity(n);
        let mut large_idx = Vec::new();
        for i in 0..n {
            let v = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
            if v & 0x8000_0000 != 0 {
                large_idx.push((i, (v & 0x7fff_ffff) as usize));
                offs.push(0u64);
            } else {
                offs.push(v as u64);
            }
        }
        for (i, li) in large_idx {
            let p = pos + li * 8;
            if p + 8 > data.len() {
                return Err("idx large-offset table truncated".into());
            }
            offs[i] = u64::from_be_bytes([
                data[p],
                data[p + 1],
                data[p + 2],
                data[p + 3],
                data[p + 4],
                data[p + 5],
                data[p + 6],
                data[p + 7],
            ]);
        }
        let pack_sha1 = hex::encode(&data[data.len() - 40..data.len() - 20]);
        let idx_sha1 = hex::encode(&data[data.len() - 20..]);
        let idx_sha1_ok = sha1_hex(&data[..data.len() - 20]) == idx_sha1;
        let entries = (0..n)
            .map(|i| IdxEntry {
                oid: oids[i].clone(),
                crc32: crcs[i],
                offset: offs[i],
            })
            .collect();
        Ok(IdxFile {
            version: 2,
            fanout,
            entries,
            pack_sha1,
            idx_sha1,
            idx_sha1_ok,
        })
    } else {
        Err("idx v1 is not supported (no magic header)".into())
    }
}
