//! Git pack v2 parser: header, object entries, ofs/ref-delta headers, zlib boundaries,
//! trailer hash. Pure Rust; never shells out to git.

use crate::gitutil::{compute_oid, inflate_boundary, ObjType, Oid};
use sha1::{Digest, Sha1};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackObjKind {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl PackObjKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            PackObjKind::Commit => "commit",
            PackObjKind::Tree => "tree",
            PackObjKind::Blob => "blob",
            PackObjKind::Tag => "tag",
            PackObjKind::OfsDelta => "ofs_delta",
            PackObjKind::RefDelta => "ref_delta",
        }
    }
    pub fn base_type(&self) -> Option<ObjType> {
        match self {
            PackObjKind::Commit => Some(ObjType::Commit),
            PackObjKind::Tree => Some(ObjType::Tree),
            PackObjKind::Blob => Some(ObjType::Blob),
            PackObjKind::Tag => Some(ObjType::Tag),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Absolute offset of the object header inside the pack file.
    pub offset: u64,
    pub kind: PackObjKind,
    /// Declared (inflated) size from the object header.
    pub declared_size: u64,
    /// For ofs-delta: relative negative offset distance.
    pub ofs_distance: Option<u64>,
    /// For ref-delta: base object id.
    pub base_oid: Option<Oid>,
    /// Absolute offset where the zlib stream begins.
    pub data_offset: u64,
    /// Number of compressed bytes consumed by the zlib stream (0 if inflate failed).
    pub comp_size: u64,
    /// Inflated payload (delta instructions for delta objects).
    pub payload: Option<Vec<u8>>,
    /// Inflate / size-fraud error, if any. The entry is still recorded.
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer: Oid,
    pub computed_trailer: Oid,
    pub trailer_ok: bool,
    /// Errors that aborted parsing after the entries collected so far.
    pub fatal: Option<String>,
}

#[derive(Debug, Error)]
pub enum PackError {
    #[error("bad pack magic")]
    BadMagic,
    #[error("unsupported pack version {0}")]
    BadVersion(u32),
    #[error("pack too small ({0} bytes)")]
    TooSmall(usize),
}

fn decode_obj_header(data: &[u8], mut pos: usize) -> Option<(u8, u64, usize)> {
    if pos >= data.len() {
        return None;
    }
    let first = data[pos];
    pos += 1;
    let type_code = (first >> 4) & 0x7;
    let mut size: u64 = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut b = first;
    while b & 0x80 != 0 {
        if pos >= data.len() || shift >= 64 {
            return None;
        }
        b = data[pos];
        pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
    }
    Some((type_code, size, pos))
}

fn decode_ofs_distance(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    if pos >= data.len() {
        return None;
    }
    let mut b = data[pos];
    pos += 1;
    let mut n: u64 = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        if pos >= data.len() {
            return None;
        }
        b = data[pos];
        pos += 1;
        n = ((n + 1) << 7) | (b & 0x7f) as u64;
    }
    Some((n, pos))
}

pub struct PackParseOptions {
    /// Max bytes a single inflated object may occupy.
    pub max_object_bytes: u64,
}

impl Default for PackParseOptions {
    fn default() -> Self {
        PackParseOptions {
            max_object_bytes: 512 * 1024 * 1024,
        }
    }
}

pub fn parse_pack(data: &[u8], opts: &PackParseOptions) -> Result<PackFile, PackError> {
    if data.len() < 12 + 20 {
        return Err(PackError::TooSmall(data.len()));
    }
    if &data[0..4] != b"PACK" {
        return Err(PackError::BadMagic);
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        return Err(PackError::BadVersion(version));
    }
    let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let mut hasher = Sha1::new();
    let trailer_start = data.len() - 20;
    hasher.update(&data[..trailer_start]);
    let computed: Oid = hasher.finalize().into();
    let mut trailer = [0u8; 20];
    trailer.copy_from_slice(&data[trailer_start..]);
    let trailer_ok = computed == trailer;

    let mut entries = Vec::new();
    let mut pos: usize = 12;
    let mut fatal: Option<String> = None;

    for _ in 0..count {
        if pos >= trailer_start {
            fatal = Some(format!(
                "pack ended early: parsed {}/{} objects",
                entries.len(),
                count
            ));
            break;
        }
        let obj_offset = pos as u64;
        let (type_code, declared_size, after_hdr) = match decode_obj_header(data, pos) {
            Some(v) => v,
            None => {
                fatal = Some(format!("bad object header at offset {}", pos));
                break;
            }
        };
        pos = after_hdr;
        let kind = match type_code {
            1 => PackObjKind::Commit,
            2 => PackObjKind::Tree,
            3 => PackObjKind::Blob,
            4 => PackObjKind::Tag,
            6 => PackObjKind::OfsDelta,
            7 => PackObjKind::RefDelta,
            c => {
                fatal = Some(format!("unknown object type {} at offset {}", c, obj_offset));
                break;
            }
        };
        let mut ofs_distance = None;
        let mut base_oid = None;
        match kind {
            PackObjKind::OfsDelta => match decode_ofs_distance(data, pos) {
                Some((n, np)) => {
                    ofs_distance = Some(n);
                    pos = np;
                }
                None => {
                    fatal = Some(format!("bad ofs-delta offset at {}", obj_offset));
                    break;
                }
            },
            PackObjKind::RefDelta => {
                if pos + 20 > trailer_start {
                    fatal = Some(format!("truncated ref-delta base at {}", obj_offset));
                    break;
                }
                let mut o = [0u8; 20];
                o.copy_from_slice(&data[pos..pos + 20]);
                base_oid = Some(o);
                pos += 20;
            }
            _ => {}
        }
        let data_offset = pos as u64;
        let (payload, comp_size, error) =
            match inflate_boundary(&data[pos..trailer_start], Some(declared_size), opts.max_object_bytes)
            {
                Ok((bytes, used)) => (Some(bytes), used as u64, None),
                Err(e) => {
                    // Record the failure; skip the rest of the pack because we cannot
                    // find the next boundary reliably.
                    (None, 0, Some(e.to_string()))
                }
            };
        let entry = PackEntry {
            offset: obj_offset,
            kind,
            declared_size,
            ofs_distance,
            base_oid,
            data_offset,
            comp_size,
            payload,
            error,
        };
        let broken = entry.error.is_some();
        entries.push(entry);
        if broken {
            fatal = Some(format!(
                "inflate failed at offset {}; remaining objects unreachable",
                obj_offset
            ));
            break;
        }
        pos += comp_size as usize;
    }

    Ok(PackFile {
        version,
        count,
        entries,
        trailer,
        computed_trailer: computed,
        trailer_ok,
        fatal,
    })
}

/// Recompute the oid of a fully reconstructed object.
pub fn object_id_for(kind: PackObjKind, payload: &[u8]) -> Option<Oid> {
    kind.base_type().map(|t| compute_oid(t, payload))
}
