//! Pack (.pack) and index (.idx v2) parsing. No system git is used.

use crate::git::{
    deflate_zlib, git_object_id, inflate_zlib_bounded, read_ofs_delta, read_pack_header_size,
    InflateError, ObjType,
};
use crc32fast::Hasher as CrcHasher;
use sha1::{Digest, Sha1};

pub const PACK_SIGNATURE: [u8; 4] = *b"PACK";
pub const IDX_SIGNATURE: [u8; 4] = [0xff, 0x74, 0x4f, 0x63];

/// A single located pack object. Oid is populated from the index or after
/// successful inflation/framing when the pack is scanned sequentially.
#[derive(Debug, Clone)]
pub struct PackEntry {
    pub index: usize,
    pub offset: u64,
    pub typ: Option<ObjType>,
    /// Declared inflated size from the entry header.
    pub declared_size: Option<u64>,
    /// Base absolute offset (ofs-delta), if resolvable syntactically.
    pub base_offset: Option<u64>,
    /// 20 byte base name for ref-delta.
    pub base_oid: Option<[u8; 20]>,
    /// Inflated payload (raw content for bases, delta bytes for deltas).
    pub payload: Option<Vec<u8>>,
    /// Byte range of the zlib stream within the pack file.
    pub zlib_start: Option<u64>,
    pub zlib_end: Option<u64>,
    /// Entry header byte range.
    pub header_start: u64,
    pub header_end: u64,
    /// Oid claimed by an idx record / computed after framing.
    pub oid: Option<[u8; 20]>,
    /// Set when inflation or header parsing failed.
    pub error: Option<String>,
    /// True when the entry could only be located by idx and inflation failed,
    /// so sequential scanning from here is not trustworthy.
    pub skipped: bool,
}

#[derive(Debug, Clone)]
pub struct IdxRecord {
    pub oid: [u8; 20],
    pub offset: u64,
    /// CRC32 of the *compressed* pack entry bytes.
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct IdxParseResult {
    pub records: Vec<IdxRecord>,
    pub fanout: [u32; 256],
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PackParseResult {
    pub entries: Vec<PackEntry>,
    pub version: u32,
    pub declared_count: u32,
    pub pack_checksum: [u8; 20],
    pub computed_checksum: [u8; 20],
    pub checksum_ok: bool,
    pub errors: Vec<String>,
}

fn be_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(buf[at..at + 4].try_into().unwrap())
}

/// Parse an idx v2 file. Only light validation here; matching against the pack
/// happens during pack parsing.
pub fn parse_idx_v2(buf: &[u8]) -> Result<IdxParseResult, String> {
    let mut errors = Vec::new();
    if buf.len() < 8 {
        return Err("idx file too small".to_string());
    }
    if buf[0..4] != IDX_SIGNATURE {
        // v1 idx: not supported by this microscope.
        if buf[0] != 0xff {
            return Err("not an idx v2 file (magic mismatch)".to_string());
        }
        return Err("idx v1 is not supported".to_string());
    }
    let version = be_u32(buf, 4);
    if version != 2 {
        return Err(format!("unsupported idx version {}", version));
    }
    let fanout_start = 8usize;
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = be_u32(buf, fanout_start + i * 4);
    }
    let count = fanout[255];
    // Fanout must be non-decreasing.
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            errors.push(format!("idx fanout decreases at bucket {}", i));
        }
    }
    let names_start = fanout_start + 256 * 4;
    let crc_start = names_start + count as usize * 20;
    let off_start = crc_start + count as usize * 4;
    let need = off_start + count as usize * 4 + 40;
    if buf.len() < need {
        return Err(format!(
            "idx truncated: needs {} bytes for {} records, have {}",
            need,
            count,
            buf.len()
        ));
    }
    let mut records = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&buf[names_start + i * 20..names_start + i * 20 + 20]);
        let crc32 = be_u32(buf, crc_start + i * 4);
        let off_raw = be_u32(buf, off_start + i * 4);
        let offset = if off_raw & 0x8000_0000 != 0 {
            let tab = (off_raw & 0x7fff_ffff) as usize;
            let tab_start = off_start + count as usize * 4;
            let at = tab_start + tab * 8;
            u64::from_be_bytes(buf[at..at + 8].try_into().unwrap())
        } else {
            off_raw as u64
        };
        records.push(IdxRecord { oid, offset, crc32 });
    }
    // Record offsets must be strictly ascending in idx order.
    for w in records.windows(2) {
        if w[0].offset >= w[1].offset {
            errors.push(format!(
                "idx offsets not strictly increasing: {} then {}",
                w[0].offset, w[1].offset
            ));
        }
    }
    // Trailer checksums: idx-pack-sha1 then idx-sha1.
    let trailer = need - 40;
    let mut pack_sha = [0u8; 20];
    pack_sha.copy_from_slice(&buf[trailer..trailer + 20]);
    let mut idx_sha = [0u8; 20];
    idx_sha.copy_from_slice(&buf[trailer + 20..trailer + 40]);
    let mut h = Sha1::new();
    h.update(&buf[..trailer + 20]);
    let computed_idx_sha: [u8; 20] = h.finalize().into();
    if computed_idx_sha != idx_sha {
        errors.push("idx file checksum mismatch".to_string());
    }
    // Pack sha exposure is handled by caller via `pack_checksum`.
    let _ = pack_sha;
    Ok(IdxParseResult { records, fanout, errors })
}

pub fn idx_pack_checksum(buf: &[u8]) -> Option<[u8; 20]> {
    if buf.len() < 40 {
        return None;
    }
    let at = buf.len() - 40;
    let mut out = [0u8; 20];
    out.copy_from_slice(&buf[at..at + 20]);
    Some(out)
}

/// Parse all objects of a pack file.
///
/// When an idx result is supplied its offsets let the scanner skip over entries
/// whose zlib stream cannot be inflated, isolating the bad object instead of
/// losing the rest of the pack.
pub fn parse_pack(
    buf: &[u8],
    idx: Option<&IdxParseResult>,
    per_object_cap: usize,
) -> Result<PackParseResult, String> {
    let mut errors = Vec::new();
    if buf.len() < 32 {
        return Err("pack file too small".to_string());
    }
    if buf[0..4] != PACK_SIGNATURE {
        return Err("bad pack signature".to_string());
    }
    let version = be_u32(buf, 4);
    if version != 2 {
        return Err(format!("unsupported pack version {}", version));
    }
    let declared_count = be_u32(buf, 8);

    // Index records by offset for lookup and CRC checking.
    let mut by_offset: std::collections::BTreeMap<u64, &IdxRecord> = std::collections::BTreeMap::new();
    if let Some(ix) = idx {
        for rec in &ix.records {
            by_offset.insert(rec.offset, rec);
        }
        if ix.records.len() as u32 != declared_count {
            errors.push(format!(
                "idx/pack mismatch: idx lists {} entries, pack header declares {}",
                ix.records.len(),
                declared_count
            ));
        }
    }

    let data_end = buf.len() - 20;
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&buf[data_end..data_end + 20]);
    let mut h = Sha1::new();
    h.update(&buf[..data_end]);
    let computed_checksum: [u8; 20] = h.finalize().into();
    let checksum_ok = computed_checksum == pack_checksum;
    if !checksum_ok {
        errors.push("pack file checksum mismatch".to_string());
    }

    let mut entries: Vec<PackEntry> = Vec::new();
    let mut pos = 12usize;
    let mut seq = 0usize;
    // Candidate next offsets from idx (strictly increasing) used to recover
    // after a failure while scanning sequentially.
    let mut idx_offsets: Vec<u64> = idx.map(|ix| ix.records.iter().map(|r| r.offset).collect())
        .unwrap_or_default();
    idx_offsets.sort_unstable();

    while pos < data_end {
        let entry_offset = pos as u64;
        let hdr = read_pack_header_size(buf, pos);
        let (typ, declared_size, hlen, header_error) = match hdr {
            Ok((t, sz, hl)) => (Some(t), Some(sz), hl, None),
            Err(e) => (None, None, 0, Some(e)),
        };
        let mut p = pos + hlen;
        let mut base_offset: Option<u64> = None;
        let mut base_oid: Option<[u8; 20]> = None;
        let mut fatal: Option<String> = header_error;
        if let Some(t) = typ {
            match t {
                ObjType::OfsDelta => match read_ofs_delta(buf, p) {
                    Ok((neg, nlen)) => {
                        p += nlen;
                        let abs = entry_offset as i64 - neg as i64;
                        if abs < 12 || abs as usize >= data_end {
                            fatal = Some(format!(
                                "ofs-delta distance out of range at offset {}: -{}",
                                entry_offset, neg
                            ));
                        } else {
                            base_offset = Some(abs as u64);
                        }
                    }
                    Err(e) => fatal = Some(e),
                },
                ObjType::RefDelta => {
                    if p + 20 > data_end {
                        fatal = Some("ref-delta base name truncated".to_string());
                    } else {
                        let mut o = [0u8; 20];
                        o.copy_from_slice(&buf[p..p + 20]);
                        p += 20;
                        base_oid = Some(o);
                    }
                }
                _ => {}
            }
        }
        let header_end = p as u64;
        let zlib_start = p;
        let rec = by_offset.get(&entry_offset).copied();
        let mut oid = rec.map(|r| r.oid);

        let mut payload = None;
        let mut zlib_end: Option<u64> = None;
        if fatal.is_none() {
            match inflate_zlib_bounded(buf, p, declared_size, per_object_cap) {
                Ok(outc) => {
                    zlib_end = Some((p + outc.input_consumed) as u64);
                    payload = Some(outc.data);
                }
                Err(InflateError::OverCap(n)) => {
                    fatal = Some(format!(
                        "declared inflated size {} exceeds per-object budget", n
                    ));
                }
                Err(other) => fatal = Some(other.message()),
            }
        }

        if let (Some(r), Some(ze)) = (rec, zlib_end) {
            let mut ch = CrcHasher::new();
            ch.update(&buf[entry_offset as usize..ze as usize]);
            let got = ch.finalize();
            if got != r.crc32 {
                let msg = format!(
                    "crc mismatch at offset {}: idx={:08x} computed={:08x}",
                    entry_offset, r.crc32, got
                );
                errors.push(msg.clone());
                fatal = Some(match fatal {
                    Some(existing) => format!("{}; {}", existing, msg),
                    None => msg,
                });
            }
        }

        if idx.is_some() && rec.is_none() {
            errors.push(format!(
                "idx/pack mismatch: no idx record for object at offset {}", entry_offset
            ));
        }

        if fatal.is_none() {
            let t = typ.unwrap();
            let pl = payload.as_ref().unwrap();
            if !t.is_delta() {
                let computed = git_object_id(t, pl);
                if let Some(expected) = oid {
                    if expected != computed {
                        let msg = format!(
                            "oid mismatch at offset {}: idx says {}, framing computes {}",
                            entry_offset, hex::encode(expected), hex::encode(computed)
                        );
                        errors.push(msg.clone());
                        fatal = Some(msg);
                    }
                } else {
                    oid = Some(computed);
                }
            }
        }

        if let Some(msg) = &fatal {
            errors.push(format!("offset {}: {}", entry_offset, msg));
        }

        let skipped = fatal.is_some();
        entries.push(PackEntry {
            index: seq,
            offset: entry_offset,
            typ,
            declared_size,
            base_offset,
            base_oid,
            payload,
            zlib_start: Some(zlib_start as u64),
            zlib_end,
            header_start: entry_offset,
            header_end,
            oid,
            error: fatal,
            skipped,
        });
        seq += 1;

        let next = if skipped {
            idx_offsets.iter().copied().find(|o| *o > entry_offset).map(|o| o as usize)
        } else {
            zlib_end.map(|z| z as usize)
        };
        match next {
            Some(np) if np > pos && np < data_end => pos = np,
            Some(np) if np == data_end => break,
            _ => break,
        }
    }

    // Missing idx records (offsets present in idx but never seen)?
    if let Some(ix) = idx {
        let seen: std::collections::HashSet<u64> = entries.iter().map(|e| e.offset).collect();
        for r in &ix.records {
            if !seen.contains(&r.offset) {
                errors.push(format!(
                    "idx/pack mismatch: idx references offset {} not found in pack",
                    r.offset
                ));
            }
        }
    }

    Ok(PackParseResult {
        entries,
        version,
        declared_count,
        pack_checksum,
        computed_checksum,
        checksum_ok,
        errors,
    })
}
