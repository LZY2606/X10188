//! Git pack file parsing: header, per-object type/size varints, ofs-delta and
//! ref-delta base references, zlib stream boundaries, and the trailer checksum.

use crate::hexutil;
use crate::zlib::{decompress_bounded, ZlibError};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs_delta",
            ObjType::RefDelta => "ref_delta",
        }
    }
    /// For delta types the underlying (resolved) object type is unknown until
    /// the base is resolved; full types map to themselves.
    pub fn is_delta(&self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Byte offset of the entry header inside the pack file.
    pub offset: u64,
    pub obj_type: ObjType,
    /// Size claimed by the entry header (final object size for full objects,
    /// delta payload size for deltas).
    pub claimed_size: u64,
    /// For ofs-delta: absolute offset of the base entry.
    pub base_offset: Option<u64>,
    /// For ref-delta: hex object id of the base.
    pub base_oid: Option<String>,
    /// Offset where the zlib stream starts.
    pub data_start: u64,
    /// Compressed stream length in bytes (boundary detected while inflating).
    pub compressed_len: u64,
    /// Inflated payload (full object content, or delta instructions).
    pub data: Vec<u8>,
    /// CRC32 of the raw on-disk entry bytes (header + compressed stream).
    pub crc32: u32,
    /// Non-fatal problem detected on this entry (e.g. size fraud). The entry
    /// is still positioned correctly so parsing can continue.
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    /// Trailer: sha1 over all preceding pack bytes.
    pub trailer: String,
    pub trailer_ok: bool,
    /// Fatal parse problem (entries after this point are unavailable).
    pub fatal: Option<String>,
}

fn read_type_size(buf: &[u8], mut pos: usize) -> Result<(u8, u64, usize), String> {
    if pos >= buf.len() {
        return Err("unexpected end of pack reading object header".into());
    }
    let mut byte = buf[pos];
    pos += 1;
    let obj_type = (byte >> 4) & 0x7;
    let mut size: u64 = (byte & 0x0f) as u64;
    let mut shift = 4;
    while byte & 0x80 != 0 {
        if pos >= buf.len() {
            return Err("unexpected end of pack in size varint".into());
        }
        byte = buf[pos];
        pos += 1;
        size |= ((byte & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("object size varint too large".into());
        }
    }
    Ok((obj_type, size, pos))
}

fn read_ofs_delta_base(buf: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    if pos >= buf.len() {
        return Err("unexpected end of pack in ofs-delta offset".into());
    }
    let mut byte = buf[pos];
    pos += 1;
    let mut n: u64 = (byte & 0x7f) as u64;
    while byte & 0x80 != 0 {
        if pos >= buf.len() {
            return Err("unexpected end of pack in ofs-delta offset".into());
        }
        byte = buf[pos];
        pos += 1;
        n = ((n + 1) << 7) | ((byte & 0x7f) as u64);
    }
    Ok((n, pos))
}

pub fn parse_pack(buf: &[u8]) -> PackFile {
    let mut fatal = None;
    let mut entries = Vec::new();
    let mut version = 0u32;
    let mut count = 0u32;
    let mut trailer = String::new();
    let mut trailer_ok = false;

    loop {
        // structured so we can `break` out with `fatal` set
        if buf.len() < 12 + 20 {
            fatal = Some(format!("file too small for a pack ({} bytes)", buf.len()));
            break;
        }
        if &buf[0..4] != b"PACK" {
            fatal = Some("missing PACK magic".into());
            break;
        }
        version = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version != 2 && version != 3 {
            fatal = Some(format!("unsupported pack version {version}"));
            break;
        }
        count = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        let body_end = buf.len() - 20;
        trailer = hexutil::encode(&buf[body_end..]);
        let actual = Sha1::digest(&buf[..body_end]);
        trailer_ok = hexutil::encode(&actual) == trailer;

        let mut pos = 12usize;
        for i in 0..count {
            let entry_offset = pos as u64;
            let (type_code, claimed_size, p) = match read_type_size(buf, pos) {
                Ok(v) => v,
                Err(e) => {
                    fatal = Some(format!("entry {i} @ {entry_offset}: {e}"));
                    break;
                }
            };
            pos = p;
            let obj_type = match ObjType::from_code(type_code) {
                Some(t) => t,
                None => {
                    fatal = Some(format!("entry {i} @ {entry_offset}: bad type code {type_code}"));
                    break;
                }
            };
            let mut base_offset = None;
            let mut base_oid = None;
            let mut entry_error = None;
            match obj_type {
                ObjType::OfsDelta => match read_ofs_delta_base(buf, pos) {
                    Ok((dist, p)) => {
                        pos = p;
                        if dist > entry_offset {
                            entry_error = Some(format!(
                                "ofs-delta distance {dist} points before pack start (entry @ {entry_offset})"
                            ));
                        } else {
                            base_offset = Some(entry_offset - dist);
                        }
                    }
                    Err(e) => {
                        fatal = Some(format!("entry {i} @ {entry_offset}: {e}"));
                        break;
                    }
                },
                ObjType::RefDelta => {
                    if pos + 20 > buf.len() {
                        fatal = Some(format!("entry {i} @ {entry_offset}: truncated ref-delta base"));
                        break;
                    }
                    base_oid = Some(hexutil::encode(&buf[pos..pos + 20]));
                    pos += 20;
                }
                _ => {}
            }
            let data_start = pos as u64;
            // The claimed size drives the inflation cap; a mismatch between the
            // inflated length and the claim is reported as size fraud.
            let max_out = claimed_size.min(crate::zlib::HARD_CAP as u64) as usize;
            match decompress_bounded(&buf[pos..body_end], max_out) {
                Ok((data, used)) => {
                    if data.len() as u64 != claimed_size {
                        entry_error = Some(format!(
                            "size fraud: header claims {} bytes but zlib stream yields {}",
                            claimed_size,
                            data.len()
                        ));
                    }
                    pos += used;
                    let raw = &buf[entry_offset as usize..pos];
                    let crc = crc32fast::hash(raw);
                    entries.push(PackEntry {
                        offset: entry_offset,
                        obj_type,
                        claimed_size,
                        base_offset,
                        base_oid,
                        data_start,
                        compressed_len: used as u64,
                        data,
                        crc32: crc,
                        error: entry_error,
                    });
                }
                Err(ZlibError::Overflow { produced, max_out }) => {
                    // Size fraud discovered mid-decompress: stream produces
                    // more than the header claims. We cannot trust the
                    // boundary, so parsing cannot continue past this entry.
                    let raw = &buf[entry_offset as usize..pos];
                    entries.push(PackEntry {
                        offset: entry_offset,
                        obj_type,
                        claimed_size,
                        base_offset,
                        base_oid,
                        data_start,
                        compressed_len: 0,
                        data: Vec::new(),
                        crc32: crc32fast::hash(raw),
                        error: Some(format!(
                            "size fraud: stream still growing at {produced} bytes (header claims {max_out})"
                        )),
                    });
                    fatal = Some(format!(
                        "entry {i} @ {entry_offset}: zlib stream overruns claimed size; cannot locate next entry"
                    ));
                    break;
                }
                Err(e) => {
                    fatal = Some(format!("entry {i} @ {entry_offset}: {e}"));
                    break;
                }
            }
        }
        if entries.len() == count as usize && fatal.is_none() {
            let expect = 12 + entries
                .iter()
                .map(|e| (e.data_start - e.offset) + e.compressed_len)
                .sum::<u64>() as usize;
            if expect != body_end {
                fatal = Some(format!(
                    "pack length mismatch: entries end at {expect}, trailer starts at {body_end}"
                ));
            }
        }
        break;
    }

    PackFile {
        version,
        count,
        entries,
        trailer,
        trailer_ok,
        fatal,
    }
}
