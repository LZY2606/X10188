//! Raw pack parsing: header, per-object entry headers, ofs/ref delta bases,
//! zlib stream boundaries and the trailing pack checksum. No system git.

use crate::gitobj::{inflate_bounded, is_delta, type_name};
use crc32fast::Hasher as Crc32;
use serde::Serialize;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Serialize)]
pub struct PackEntry {
    pub offset: u64,
    pub obj_type: u8,
    pub type_name: String,
    /// Size declared in the entry header (delta entries: size of delta data).
    pub declared_size: u64,
    /// Absolute offset of the compressed zlib stream.
    pub data_start: u64,
    /// Exact length of the compressed zlib stream.
    pub data_len: u64,
    /// CRC32 of the raw entry bytes (header + compressed data), as idx stores.
    pub crc32: u32,
    /// For ofs-delta: negative distance; base sits at `offset - base_ofs`.
    pub base_ofs: Option<u64>,
    /// For ref-delta: hex object id of the base.
    pub base_oid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_ok: bool,
    pub errors: Vec<String>,
}

fn parse_entry_header(data: &[u8], pos: usize) -> Result<(u8, u64, usize), String> {
    if pos >= data.len() {
        return Err("entry header out of bounds".into());
    }
    let mut b = data[pos];
    let mut p = pos + 1;
    let obj_type = (b >> 4) & 0x7;
    let mut size: u64 = (b & 0x0f) as u64;
    let mut shift = 4u32;
    while b & 0x80 != 0 {
        if p >= data.len() {
            return Err("entry size varint truncated".into());
        }
        b = data[p];
        p += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("entry size varint overflow".into());
        }
    }
    Ok((obj_type, size, p - pos))
}

fn parse_ofs_distance(data: &[u8], pos: usize) -> Result<(u64, usize), String> {
    if pos >= data.len() {
        return Err("ofs-delta distance truncated".into());
    }
    let mut b = data[pos];
    let mut p = pos + 1;
    let mut dist: u64 = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        if p >= data.len() {
            return Err("ofs-delta distance truncated".into());
        }
        b = data[p];
        p += 1;
        dist = ((dist + 1) << 7) | ((b & 0x7f) as u64);
    }
    Ok((dist, p - pos))
}

/// Inflate one entry's zlib stream with an output cap of `declared + 1` so
/// that streams inflating past their declared size are caught as deception.
pub fn inflate_entry(pack: &[u8], e: &PackEntry) -> Result<Vec<u8>, String> {
    let start = e.data_start as usize;
    let end = (e.data_start + e.data_len) as usize;
    if end > pack.len() {
        return Err("entry data range out of bounds".into());
    }
    let cap = (e.declared_size as usize).saturating_add(1);
    let (out, _) = inflate_bounded(&pack[start..end], cap)?;
    if out.len() as u64 != e.declared_size {
        return Err(format!(
            "size deception: header declares {}, stream yields {}",
            e.declared_size,
            out.len()
        ));
    }
    Ok(out)
}

pub fn parse_pack(data: &[u8]) -> Result<PackFile, String> {
    if data.len() < 12 + 20 {
        return Err("pack too small for header + trailer".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("missing PACK magic".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        return Err(format!("unsupported pack version {version}"));
    }
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());

    let body = &data[..data.len() - 20];
    let trailer = &data[data.len() - 20..];
    let trailer_ok = Sha1::digest(body).as_slice() == trailer;

    let mut entries = Vec::new();
    let mut errors = Vec::new();
    let mut pos = 12usize;
    for i in 0..count {
        let entry_start = pos;
        if pos >= body.len() {
            errors.push(format!("entry {i}: offset {pos} beyond pack body"));
            break;
        }
        let (obj_type, size, hlen) = match parse_entry_header(body, pos) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("entry {i} @ {entry_start}: {e}"));
                break;
            }
        };
        pos += hlen;
        let mut base_ofs = None;
        let mut base_oid = None;
        match obj_type {
            6 => match parse_ofs_distance(body, pos) {
                Ok((d, n)) => {
                    base_ofs = Some(d);
                    pos += n;
                }
                Err(e) => {
                    errors.push(format!("entry {i} @ {entry_start}: {e}"));
                    break;
                }
            },
            7 => {
                if pos + 20 > body.len() {
                    errors.push(format!("entry {i} @ {entry_start}: ref-delta base oid truncated"));
                    break;
                }
                base_oid = Some(hex::encode(&body[pos..pos + 20]));
                pos += 20;
            }
            1..=4 => {}
            t => {
                errors.push(format!("entry {i} @ {entry_start}: unknown object type {t}"));
                break;
            }
        }
        let data_start = pos;
        // Probe the zlib boundary with a generous cap; exact size validation
        // against the declared size happens at resolution time.
        let cap = (size as usize).saturating_add(1);
        let consumed = match inflate_bounded(&body[data_start..], cap) {
            Ok((_out, n)) => n,
            Err(e) => {
                errors.push(format!(
                    "entry {i} @ {entry_start} ({}): zlib boundary: {e}",
                    type_name(obj_type)
                ));
                break;
            }
        };
        pos = data_start + consumed;
        let mut crc = Crc32::new();
        crc.update(&body[entry_start..pos]);
        entries.push(PackEntry {
            offset: entry_start as u64,
            obj_type,
            type_name: type_name(obj_type).to_string(),
            declared_size: size,
            data_start: data_start as u64,
            data_len: consumed as u64,
            crc32: crc.finalize(),
            base_ofs,
            base_oid,
        });
        let _ = is_delta(obj_type);
    }
    if entries.len() as u32 != count {
        errors.push(format!(
            "header count {count} but parsed {} entries",
            entries.len()
        ));
    }
    Ok(PackFile {
        version,
        count,
        entries,
        trailer_ok,
        errors,
    })
}
