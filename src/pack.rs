//! Pack file and pack index (v2) parsing. No system git involved.
use crate::gitobj::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackEntry {
    /// Absolute offset of the entry header inside the pack file.
    pub offset: u64,
    pub obj_type: ObjType,
    /// Declared (inflated) size from the entry header.
    pub declared_size: u64,
    /// Offset where the zlib stream (or delta base ref) begins.
    pub data_offset: u64,
    /// For ofs-delta: distance back to the base entry.
    pub ofs_distance: Option<u64>,
    /// For ofs-delta: absolute offset of the base entry.
    pub base_offset: Option<u64>,
    /// For ref-delta: hex oid of the base object.
    pub base_oid: Option<String>,
    /// Inflated raw data (object content for base types, delta program for deltas).
    pub raw: Vec<u8>,
    /// Compressed length of the zlib stream.
    pub compressed_len: u64,
    /// crc32 over the on-disk entry bytes (header..end of zlib stream).
    pub crc32: u32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_sha1: String,
    /// True when the trailer matches the recomputed sha1 of the pack body.
    pub trailer_ok: bool,
    pub errors: Vec<String>,
}

const INFLATE_CAP: u64 = 512 * 1024 * 1024;

pub fn parse_pack(buf: &[u8]) -> Result<PackFile, String> {
    if buf.len() < 12 + 20 {
        return Err("file too small to be a pack".into());
    }
    if &buf[0..4] != b"PACK" {
        return Err("missing PACK magic".into());
    }
    let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if version != 2 && version != 3 {
        return Err(format!("unsupported pack version {}", version));
    }
    let count = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let body_end = buf.len() - 20;
    let trailer_sha1 = hex::encode(&buf[body_end..]);
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(&buf[..body_end]);
    let trailer_ok = hex::encode(h.finalize()) == trailer_sha1;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos = 12usize;
    for idx in 0..count {
        if pos >= body_end {
            errors.push(format!(
                "pack ended after {} of {} declared entries",
                idx, count
            ));
            break;
        }
        let entry_offset = pos as u64;
        match parse_entry(buf, pos, body_end) {
            Ok((entry, next)) => {
                entries.push(entry);
                pos = next;
            }
            Err(e) => {
                errors.push(format!("entry {} at offset {}: {}", idx, entry_offset, e));
                break; // cannot resync a pack stream reliably
            }
        }
    }
    if pos != body_end && errors.is_empty() {
        errors.push(format!(
            "pack body has {} unparsed bytes before trailer",
            body_end - pos
        ));
    }
    Ok(PackFile {
        version,
        count,
        entries,
        trailer_sha1,
        trailer_ok,
        errors,
    })
}

fn parse_entry(buf: &[u8], pos: usize, body_end: usize) -> Result<(PackEntry, usize), String> {
    let entry_offset = pos as u64;
    let (type_code, declared_size, hdr_len) = parse_entry_header(&buf[pos..body_end])?;
    let obj_type = ObjType::from_code(type_code)
        .ok_or_else(|| format!("unknown object type code {}", type_code))?;
    let mut p = pos + hdr_len;
    let mut ofs_distance = None;
    let mut base_offset = None;
    let mut base_oid = None;
    match obj_type {
        ObjType::OfsDelta => {
            let (dist, used) = parse_ofs_distance(&buf[p..body_end])?;
            p += used;
            if dist > entry_offset {
                return Err(format!(
                    "ofs-delta distance {} points before pack start (entry at {})",
                    dist, entry_offset
                ));
            }
            ofs_distance = Some(dist);
            base_offset = Some(entry_offset - dist);
        }
        ObjType::RefDelta => {
            if p + 20 > body_end {
                return Err("truncated ref-delta base oid".into());
            }
            base_oid = Some(hex::encode(&buf[p..p + 20]));
            p += 20;
        }
        _ => {}
    }
    let data_offset = p as u64;
    let (raw, used) = inflate_bounded(&buf[p..body_end], INFLATE_CAP)
        .map_err(|e| format!("inflate failed for {} entry: {}", obj_type.label(), e))?;
    if raw.len() as u64 != declared_size {
        return Err(format!(
            "size deception: header declared {} bytes but zlib produced {}",
            declared_size,
            raw.len()
        ));
    }
    let end = p + used;
    let crc = crc32(&buf[pos..end]);
    Ok((
        PackEntry {
            offset: entry_offset,
            obj_type,
            declared_size,
            data_offset,
            ofs_distance,
            base_offset,
            base_oid,
            raw,
            compressed_len: used as u64,
            crc32: crc,
        },
        end,
    ))
}

pub fn crc32(buf: &[u8]) -> u32 {
    // IEEE crc32, table-driven.
    let mut table = [0u32; 256];
    for (i, e) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
        }
        *e = c;
    }
    let mut c: u32 = 0xFFFFFFFF;
    for &b in buf {
        c = table[((c ^ b as u32) & 0xFF) as usize] ^ (c >> 8);
    }
    c ^ 0xFFFFFFFF
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IdxFile {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: String,
    pub idx_sha1: String,
    pub trailer_ok: bool,
}

pub fn parse_idx(buf: &[u8]) -> Result<IdxFile, String> {
    if buf.len() < 8 + 256 * 4 + 40 {
        return Err("file too small to be an idx".into());
    }
    if &buf[0..4] != b"\xfftOc" {
        return Err("missing idx magic".into());
    }
    let version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if version != 2 {
        return Err(format!("unsupported idx version {}", version));
    }
    let mut fanout = [0u32; 256];
    let mut p = 8usize;
    for f in fanout.iter_mut() {
        *f = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
        p += 4;
    }
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            return Err("fanout table is not monotonic".into());
        }
    }
    let n = fanout[255] as usize;
    let need = p + n * 20 + n * 4 + n * 4 + 40;
    if buf.len() < need {
        return Err(format!("idx truncated: need {} bytes, have {}", need, buf.len()));
    }
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        oids.push(hex::encode(&buf[p..p + 20]));
        p += 20;
    }
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        crcs.push(u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]));
        p += 4;
    }
    let mut offs = Vec::with_capacity(n);
    let mut large_idx = Vec::new();
    for i in 0..n {
        let v = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
        p += 4;
        if v & 0x8000_0000 != 0 {
            large_idx.push((i, (v & 0x7fff_ffff) as usize));
            offs.push(0u64);
        } else {
            offs.push(v as u64);
        }
    }
    for (i, li) in large_idx {
        let base = p + li * 8;
        if base + 8 > buf.len() {
            return Err("idx large-offset table out of range".into());
        }
        offs[i] = u64::from_be_bytes([
            buf[base], buf[base + 1], buf[base + 2], buf[base + 3],
            buf[base + 4], buf[base + 5], buf[base + 6], buf[base + 7],
        ]);
    }
    let pack_sha1 = hex::encode(&buf[buf.len() - 40..buf.len() - 20]);
    let idx_sha1 = hex::encode(&buf[buf.len() - 20..]);
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(&buf[..buf.len() - 20]);
    let trailer_ok = hex::encode(h.finalize()) == idx_sha1;

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        entries.push(IdxEntry {
            oid: oids[i].clone(),
            crc32: crcs[i],
            offset: offs[i],
        });
    }
    Ok(IdxFile {
        fanout,
        entries,
        pack_sha1,
        idx_sha1,
        trailer_ok,
    })
}
