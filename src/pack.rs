use serde::Serialize;
use sha1::{Digest, Sha1};

use crate::encoding::{
    git_object_id, read_be, read_entry_header, read_ofs_distance, zlib_inflate_range,
};
use crate::types::{GitType, Oid};

#[derive(Clone, Debug, Serialize)]
pub struct PackEntry {
    /// Offset of the entry header inside the pack file.
    pub offset: u64,
    pub kind_code: u8,
    pub kind_name: String,
    /// Size declared by the entry header / delta header.
    pub declared_size: u64,
    /// Length of the inflated zlib payload.
    pub inflated_size: u64,
    /// Raw [start, end) of the zlib stream in the file.
    pub zlib_start: u64,
    pub zlib_end: u64,
    /// Inflated payload (delta bytes or raw object content).
    #[serde(skip)]
    pub payload: Vec<u8>,
    /// For ofs-delta: absolute offset of the base entry.
    pub base_offset: Option<u64>,
    /// For ref-delta: 20-byte base object id.
    pub base_oid_hex: Option<String>,
    /// Index-claimed object id, if this pack has a matching index.
    pub claimed_oid_hex: Option<String>,
    /// CRC of the *compressed* entry data as listed in the index.
    pub index_crc: Option<u32>,
    pub parse_error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackInfo {
    pub version: u32,
    pub count: u32,
    /// SHA-1 over every preceding pack byte; checked vs the 20-byte trailer.
    pub trailer_hex: String,
    pub computed_checksum_hex: String,
    pub checksum_ok: bool,
    pub entries: Vec<PackEntry>,
    pub errors: Vec<String>,
}

/// Parse a pack file, locating the header, every entry header and the exact
/// zlib stream boundaries. Bad entries are recorded, never panic.
pub fn parse_pack(data: &[u8]) -> PackInfo {
    let mut errors = Vec::new();
    let mut entries = Vec::new();

    if data.len() < 12 {
        errors.push("pack shorter than 12-byte header".into());
        return PackInfo {
            version: 0,
            count: 0,
            trailer_hex: String::new(),
            computed_checksum_hex: String::new(),
            checksum_ok: false,
            entries,
            errors,
        };
    }
    if &data[0..4] != b"PACK" {
        errors.push(format!("bad pack signature: {:?}", &data[0..4]));
    }
    let version = read_be(&data[4..8], 4) as u32;
    let count = read_be(&data[8..12], 4) as u32;
    if version != 2 {
        errors.push(format!("unsupported pack version {version}"));
    }

    let mut h = Sha1::new();
    h.update(&data[..data.len().saturating_sub(20).min(data.len())]);

    let mut pos = 12usize;
    let data_end = data.len().saturating_sub(20);
    for _ in 0..count {
        if pos >= data_end {
            errors.push(format!("entry starts at {pos} but pack body ended"));
            break;
        }
        let offset = pos as u64;
        let entry = match read_entry_header(data, pos) {
            Ok((code, declared_size, after_header)) => {
                let kind = match GitType::from_code(code) {
                    Some(k) => k,
                    None => {
                        errors
                            .push(format!("entry @{offset}: unknown object type code {code}"));
                        break;
                    }
                };
                let mut base_offset = None;
                let mut base_oid_hex = None;
                let mut p = after_header;
                if kind == GitType::OfsDelta {
                    match read_ofs_distance(data, p) {
                        Ok((distance, np)) => {
                            base_offset = Some(offset - distance);
                            p = np;
                        }
                        Err(e) => {
                            errors.push(format!("entry @{offset}: {e}"));
                            break;
                        }
                    }
                } else if kind == GitType::RefDelta {
                    if p + 20 > data_end {
                        errors.push(format!("entry @{offset}: truncated ref-delta base oid"));
                        break;
                    }
                    base_oid_hex = Some(hex::encode(&data[p..p + 20]));
                    p += 20;
                }
                let zlib_start = p;
                match zlib_inflate_range(&data[p..data_end]) {
                    Ok((payload, consumed)) => {
                        let inflated_size = payload.len() as u64;
                        let mut parse_error = None;
                        if inflated_size != declared_size {
                            let msg = format!(
                                "size spoof: header declares {declared_size}, inflated is {inflated_size}"
                            );
                            errors.push(format!("entry @{offset}: {msg}"));
                            parse_error = Some(msg);
                        }
                        let e = PackEntry {
                            offset,
                            kind_code: code,
                            kind_name: kind.name().into(),
                            declared_size,
                            inflated_size,
                            zlib_start: zlib_start as u64,
                            zlib_end: (zlib_start + consumed) as u64,
                            payload,
                            base_offset,
                            base_oid_hex,
                            claimed_oid_hex: None,
                            index_crc: None,
                            parse_error,
                        };
                        pos = zlib_start + consumed;
                        e
                    }
                    Err(e) => {
                        errors.push(format!(
                            "entry @{offset}: zlib decompression failed at {zlib_start}: {e}"
                        ));
                        break;
                    }
                }
            }
            Err(e) => {
                errors.push(format!("entry @{offset}: {e}"));
                break;
            }
        };
        entries.push(entry);
    }

    if entries.len() != count as usize && !errors.iter().any(|e| e.contains("zlib")) {
        // already recorded a terminating error in most cases
    }

    let (trailer_hex, computed_checksum_hex, checksum_ok) = if data.len() >= 20 {
        let trailer = &data[data.len() - 20..];
        let mut h2 = Sha1::new();
        h2.update(&data[..data.len() - 20]);
        let computed = h2.finalize();
        let ok = computed.as_slice() == trailer;
        if !ok {
            errors.push("pack SHA-1 checksum trailer mismatch".into());
        }
        (
            hex::encode(trailer),
            hex::encode(computed),
            ok,
        )
    } else {
        (String::new(), String::new(), false)
    };

    PackInfo {
        version,
        count,
        trailer_hex,
        computed_checksum_hex,
        checksum_ok,
        entries,
        errors,
    }
}

/// Recompute the Git object id for a fully reconstructed non-delta payload.
pub fn hash_payload(kind: GitType, payload: &[u8]) -> Oid {
    git_object_id(kind, payload)
}
