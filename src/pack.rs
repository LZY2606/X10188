//! PACK (v2) parser: headers, object types, OFS/REF deltas, zlib boundaries,
//! per-entry CRC32 and trailing SHA-1 checksum verification.

use crate::git::{parse_ofs_distance, parse_pack_entry_header, GitType};
use crate::zlib_util::{inflate_one, InflateError};
use sha2::Digest;

pub const PACK_MAGIC: &[u8; 4] = b"PACK";
/// Safety cap for a single inflated stream (the point at which a size lie that
/// only shows up mid-decompression is arrested).
pub const MAX_INFLATE: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub ordinal: usize,
    pub offset: u64,
    pub header_len: usize,
    pub type_code: u8,
    pub type_name: String,
    pub declared_size: u64,
    /// OFS-delta only.
    pub ofs_distance: Option<u64>,
    pub ofs_header_len: Option<usize>,
    pub base_offset: Option<i64>,
    /// REF-delta only.
    pub base_oid: Option<[u8; 20]>,
    /// Offset of the first zlib byte.
    pub zlib_offset: u64,
    pub compressed_len: usize,
    pub inflated_len: usize,
    pub adler_ok: bool,
    pub crc32: u32,
    /// SHA-256 of the inflated payload.
    pub content_sha256: String,
    pub size_matches_header: bool,
    pub inflated: Vec<u8>,
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackIssue {
    pub at_offset: u64,
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub version: u32,
    pub num_objects: u32,
    pub entries: Vec<PackEntry>,
    pub issues: Vec<PackIssue>,
    pub trailer_expected: [u8; 20],
    pub trailer_actual: [u8; 20],
    pub trailer_ok: bool,
    pub scan_completed: bool,
    pub raw_sha256: String,
}

fn crc32_ieee(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for n in 0..256u32 {
        let mut c = n;
        for _ in 0..8 {
            if c & 1 != 0 {
                c = 0xedb88320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
        }
        table[n as usize] = c;
    }
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ 0xffff_ffff
}

fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub fn parse_pack(raw: &[u8]) -> Result<ParsedPack, String> {
    use sha2::Digest;
    let raw_sha256 = hex::encode(sha2::Sha256::digest(raw));

    if raw.len() < 32 {
        return Err("file shorter than 32 bytes".into());
    }
    if &raw[0..4] != PACK_MAGIC {
        return Err("missing PACK magic".into());
    }
    let version = u32be(&raw[4..8]);
    if version != 2 {
        return Err(format!("unsupported pack version {version}"));
    }
    let num_objects = u32be(&raw[8..12]);

    let mut issues = Vec::new();
    let mut entries = Vec::new();
    let mut pos: usize = 12;
    let trailer_at = raw.len() - 20;
    let mut scan_completed = true;

    while (pos as u64) < trailer_at as u64 {
        let entry_offset = pos;
        let header = match parse_pack_entry_header(&raw[pos..]) {
            Some(h) => h,
            None => {
                issues.push(PackIssue {
                    at_offset: pos as u64,
                    code: "truncated_entry_header".into(),
                    detail: "ran off the end while reading the entry header".into(),
                });
                scan_completed = false;
                break;
            }
        };
        let (type_code, declared_size, header_len) = header;
        let ty = match GitType::from_pack_code(type_code) {
            Some(t) => t,
            None => {
                issues.push(PackIssue {
                    at_offset: pos as u64,
                    code: "unknown_object_type".into(),
                    detail: format!("pack type code {type_code} is not valid"),
                });
                scan_completed = false;
                break;
            }
        };

        let mut ofs_distance = None;
        let mut ofs_header_len = None;
        let mut base_offset: Option<i64> = None;
        let mut base_oid: Option<[u8; 20]> = None;
        pos += header_len;

        if ty == GitType::OfsDelta {
            match parse_ofs_distance(&raw[pos..]) {
                Some((dist, n)) => {
                    ofs_distance = Some(dist);
                    ofs_header_len = Some(n);
                    if dist > entry_offset as u64 {
                        issues.push(PackIssue {
                            at_offset: entry_offset as u64,
                            code: "ofs_distance_underflow".into(),
                            detail: format!(
                                "negative offset -{dist} runs before the start of the pack"
                            ),
                        });
                        base_offset = None;
                    } else {
                        base_offset = Some(entry_offset as i64 - dist as i64);
                    }
                    pos += n;
                }
                None => {
                    issues.push(PackIssue {
                        at_offset: pos as u64,
                        code: "truncated_ofs_distance".into(),
                        detail: "could not read the OFS_DELTA relative offset".into(),
                    });
                    scan_completed = false;
                    break;
                }
            }
        } else if ty == GitType::RefDelta {
            if pos + 20 > trailer_at {
                issues.push(PackIssue {
                    at_offset: pos as u64,
                    code: "truncated_ref_oid".into(),
                    detail: "REF_DELTA base object id runs past the pack trailer".into(),
                });
                scan_completed = false;
                break;
            }
            let mut a = [0u8; 20];
            a.copy_from_slice(&raw[pos..pos + 20]);
            base_oid = Some(a);
            pos += 20;
        }

        let zlib_offset = pos;
        let inflate_result = inflate_one(&raw[zlib_offset..trailer_at], MAX_INFLATE);
        let mut entry = PackEntry {
            ordinal: entries.len(),
            offset: entry_offset as u64,
            header_len,
            type_code,
            type_name: ty.name().to_string(),
            declared_size,
            ofs_distance,
            ofs_header_len,
            base_offset,
            base_oid,
            zlib_offset: zlib_offset as u64,
            compressed_len: 0,
            inflated_len: 0,
            adler_ok: false,
            crc32: 0,
            content_sha256: String::new(),
            size_matches_header: false,
            inflated: Vec::new(),
            parse_error: None,
        };

        match inflate_result {
            Ok(inf) => {
                let end = entry_offset + header_len
                    + ofs_header_len.unwrap_or(0)
                    + if ty == GitType::RefDelta { 20 } else { 0 }
                    + inf.compressed_len;
                entry.compressed_len = inf.compressed_len;
                entry.inflated_len = inf.data.len();
                entry.adler_ok = inf.adler_ok;
                entry.crc32 = crc32_ieee(&raw[entry_offset..end]);
                entry.inflated = inf.data;
                let mut h = sha2::Sha256::new();
                h.update(&entry.inflated);
                entry.content_sha256 = hex::encode(h.finalize());
                entry.size_matches_header = entry.inflated_len as u64 == declared_size;
                if !entry.size_matches_header {
                    issues.push(PackIssue {
                        at_offset: entry_offset as u64,
                        code: "size_spoof".into(),
                        detail: format!(
                            "entry header claims {declared_size} bytes but zlib produced {}",
                            entry.inflated_len
                        ),
                    });
                }
                if ofs_distance.is_some() && base_offset.is_none() {
                    entry.parse_error = Some("ofs distance runs before pack start".into());
                }
                pos = end;
            }
            Err(e @ (InflateError::Corrupt(_) | InflateError::ExceedsMaxOutput { .. })) => {
                let detail = match e {
                    InflateError::Corrupt(msg) => format!("zlib stream corrupt: {msg}"),
                    InflateError::ExceedsMaxOutput { produced } => format!(
                        "inflated size exceeded safety cap {MAX_INFLATE} (produced {produced}); likely size spoof / bomb"
                    ),
                };
                entry.parse_error = Some(detail.clone());
                issues.push(PackIssue {
                    at_offset: entry_offset as u64,
                    code: "inflate_failed".into(),
                    detail,
                });
                entries.push(entry);
                scan_completed = false;
                break;
            }
        }
        entries.push(entry);
    }

    let mut trailer_expected = [0u8; 20];
    trailer_expected.copy_from_slice(&raw[trailer_at..trailer_at + 20]);
    let mut hasher = sha1::Sha1::new();
    hasher.update(&raw[..trailer_at]);
    let trailer_actual: [u8; 20] = hasher.finalize().into();
    let trailer_ok = trailer_actual == trailer_expected;
    if !trailer_ok {
        issues.push(PackIssue {
            at_offset: trailer_at as u64,
            code: "pack_checksum_mismatch".into(),
            detail: "trailing SHA-1 does not match the pack contents".into(),
        });
    }
    if entries.len() as u32 != num_objects && scan_completed {
        issues.push(PackIssue {
            at_offset: 12,
            code: "object_count_mismatch".into(),
            detail: format!(
                "header declares {num_objects} objects but {n} were parsed",
                n = entries.len()
            ),
        });
    }

    Ok(ParsedPack {
        version,
        num_objects,
        entries,
        issues,
        trailer_expected,
        trailer_actual,
        trailer_ok,
        scan_completed,
        raw_sha256,
    })
}

/// Encode one pack entry (test fixture builder). `extra` is the ref oid / ofs
/// varint placed between the entry header and the zlib stream.
pub fn build_pack_entry(ty: GitType, extra: &[u8], payload: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    let mut out = encode_pack_entry_header(ty.code().unwrap(), payload.len() as u64);
    out.extend_from_slice(extra);
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(payload).unwrap();
    out.extend_from_slice(&enc.finish().unwrap());
    out
}


