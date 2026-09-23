//! Minimal pure-Rust git PACK v2 parser. No system git is used.

use crate::crc32::crc32;
use crate::delta::DeltaError;
use crate::oid::Oid;
use flate2::{Decompress, FlushDecompress};

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
    fn from_bits(b: u8) -> Option<ObjType> {
        match b {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }

    pub fn base_kind_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum DeltaRef {
    Ofs { abs_offset: u64, negative_distance: u64 },
    Ref(Oid),
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Byte offset of the entry's first header byte in the pack.
    pub offset: u64,
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub delta_ref: Option<DeltaRef>,
    /// Decompressed bytes: base content or delta instructions.
    pub data: Vec<u8>,
    /// CRC32 over the exact on-disk bytes of this entry (header+zlib stream).
    pub stored_crc: Option<u32>,
    pub computed_crc: Option<u32>,
    /// [start, end) byte range of the zlib stream in the file.
    pub zlib_start: u64,
    pub zlib_end: u64,
    pub parse_issue: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PackInfo {
    pub version: u32,
    pub count: u32,
    pub data: Vec<u8>,
    pub entries: Vec<PackEntry>,
    /// 20-byte SHA1 over all pack bytes before the trailer.
    pub stored_trailer: Option<Oid>,
    pub computed_trailer: Option<Oid>,
    pub header_issue: Option<String>,
}

pub const MAX_OBJECT: usize = 512 * 1024 * 1024;

fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse one entry header starting at `pos`.
/// Returns (type, declared size, header length, delta ref extra bytes).
fn read_entry_header(data: &[u8], pos: usize) -> Result<(ObjType, u64, usize), String> {
    let b0 = *data.get(pos).ok_or("unexpected EOF in object header")?;
    let obj_type = ObjType::from_bits((b0 >> 4) & 0x7).ok_or_else(|| {
        format!("unknown/reserved object type {} at offset {}", (b0 >> 4) & 0x7, pos)
    })?;
    let mut size = (b0 & 0x0f) as u64;
    let mut shift = 4u32;
    let mut len = 1usize;
    let mut p = pos + 1;
    if b0 & 0x80 != 0 {
        loop {
            let b = *data.get(p).ok_or("unexpected EOF in object size continuation")?;
            p += 1;
            len += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
            if shift > 63 {
                return Err("object size varint too long".into());
            }
        }
    }
    Ok((obj_type, size, len))
}

fn read_ofs_distance(data: &[u8], mut p: usize) -> Result<(u64, usize), String> {
    let b0 = *data.get(p).ok_or("unexpected EOF in ofs-delta")?;
    let mut c = (b0 & 0x7f) as u64;
    let mut n = 1usize;
    p += 1;
    let mut byte = b0;
    while byte & 0x80 != 0 {
        byte = *data.get(p).ok_or("unexpected EOF in ofs-delta distance")?;
        p += 1;
        n += 1;
        c += 1;
        c <<= 7;
        c |= (byte & 0x7f) as u64;
    }
    Ok((c, n))
}

/// Inflate one zlib stream starting at `start`, growing output in chunks so a
/// lying size header is caught as soon as output crosses the declared length
/// (or the hard safety cap). Returns (bytes, stream end offset).
fn inflate_one(data: &[u8], start: usize, declared: u64) -> Result<(Vec<u8>, usize), String> {
    let mut dec = Decompress::new(true);
    let mut out = Vec::new();
    let cap = declared as usize;
    if declared as usize > MAX_OBJECT {
        return Err(format!(
            "declared object size {} exceeds hard cap {}",
            declared, MAX_OBJECT
        ));
    }
    let mut input_pos = start;
    loop {
        let want = (cap.saturating_sub(out.len()).max(4096)).min(64 * 1024);
        let old_len = out.len();
        out.resize(old_len + want, 0u8);
        let in_before = dec.total_in();
        let status = dec
            .decompress(
                &data[input_pos..],
                &mut out[old_len..],
                FlushDecompress::None,
            )
            .map_err(|e| format!("zlib error: {e}"))?;
        let consumed = (dec.total_in() - in_before) as usize;
        input_pos += consumed;
        let produced = dec.total_out() as usize;
        out.truncate(produced);
        if produced > cap {
            return Err(format!(
                "size spoof: header declared {declared} bytes but stream already produced {produced}"
            ));
        }
        if produced > MAX_OBJECT {
            return Err(format!("object exceeds hard cap of {MAX_OBJECT} bytes"));
        }
        use flate2::Status;
        match status {
            Status::StreamEnd => {
                return Ok((out, start + dec.total_in() as usize));
            }
            Status::Ok => {
                if consumed == 0 && (dec.total_out() as usize) == old_len {
                    // Defensive: no progress would loop forever.
                    return Err("zlib made no progress (corrupt stream)".into());
                }
            }
            Status::BufError => {
                // Should not happen since we just resized; bail to avoid a loop.
                return Err("zlib buffer error".into());
            }
        }
    }
}

pub fn parse_pack(data: Vec<u8>) -> PackInfo {
    let mut info = PackInfo {
        version: 0,
        count: 0,
        data,
        entries: Vec::new(),
        stored_trailer: None,
        computed_trailer: None,
        header_issue: None,
    };

    macro_rules! fail_header {
        ($($arg:tt)*) => {{
            info.header_issue = Some(format!($($arg)*));
            return info;
        }};
    }

    if info.data.len() < 12 {
        fail_header!("file shorter than 12-byte pack header ({} bytes)", info.data.len());
    }
    if &info.data[0..4] != b"PACK" {
        fail_header!("bad pack magic: {:02x?}", &info.data[0..4]);
    }
    info.version = read_u32(&info.data[4..8]);
    if info.version != 2 {
        fail_header!("unsupported pack version {}", info.version);
    }
    info.count = read_u32(&info.data[8..12]);

    let mut pos = 12usize;
    for idx in 0..info.count as usize {
        let entry_offset = pos as u64;
        let hdr = match read_entry_header(&info.data, pos) {
            Ok(h) => h,
            Err(e) => {
                info.header_issue =
                    Some(format!("entry {idx} at offset {pos}: {e}; cannot continue this pack"));
                return info;
            }
        };
        let (obj_type, declared_size, hdr_len) = hdr;
        pos += hdr_len;

        let mut delta_ref = None;
        if obj_type == ObjType::OfsDelta {
            match read_ofs_distance(&info.data, pos) {
                Ok((dist, n)) => {
                    pos += n;
                    let abs = entry_offset.checked_sub(dist);
                    match abs {
                        Some(a) => delta_ref = Some(DeltaRef::Ofs { abs_offset: a, negative_distance: dist }),
                        None => {
                            let entry = PackEntry {
                                offset: entry_offset,
                                obj_type,
                                declared_size,
                                delta_ref: Some(DeltaRef::Ofs {
                                    abs_offset: entry_offset.saturating_sub(dist),
                                    negative_distance: dist,
                                }),
                                data: Vec::new(),
                                stored_crc: None,
                                computed_crc: None,
                                zlib_start: pos as u64,
                                zlib_end: pos as u64,
                                parse_issue: Some(format!(
                                    "ofs-delta negative distance {dist} underflows before pack start"
                                )),
                            };
                            info.entries.push(entry);
                            break;
                        }
                    }
                }
                Err(e) => {
                    info.header_issue =
                        Some(format!("entry {idx} at offset {entry_offset}: {e}"));
                    return info;
                }
            }
        } else if obj_type == ObjType::RefDelta {
            if pos + 20 > info.data.len() {
                info.header_issue =
                    Some(format!("entry {idx}: truncated ref-delta base name"));
                return info;
            }
            delta_ref = Some(DeltaRef::Ref(
                Oid::from_bytes(&info.data[pos..pos + 20]).unwrap(),
            ));
            pos += 20;
        }

        let zlib_start = pos;
        let inflate = inflate_one(&info.data, zlib_start, declared_size);
        match inflate {
            Ok((raw, end)) => {
                pos = end;
                let range_end = pos;
                let stored = crc32(&info.data[entry_offset as usize..range_end]);
                info.entries.push(PackEntry {
                    offset: entry_offset,
                    obj_type,
                    declared_size,
                    delta_ref,
                    data: raw,
                    stored_crc: None,
                    computed_crc: Some(stored),
                    zlib_start: zlib_start as u64,
                    zlib_end: end as u64,
                    parse_issue: None,
                });
            }
            Err(e) => {
                // Record the broken entry with zlib boundary up to EOF as evidence;
                // keep scanning is impossible without a stream boundary, so stop.
                let end = info.data.len().saturating_sub(20);
                info.entries.push(PackEntry {
                    offset: entry_offset,
                    obj_type,
                    declared_size,
                    delta_ref,
                    data: Vec::new(),
                    stored_crc: None,
                    computed_crc: None,
                    zlib_start: zlib_start as u64,
                    zlib_end: end as u64,
                    parse_issue: Some(e),
                });
                info.header_issue = Some(format!(
                    "entry {idx} at offset {entry_offset}: zlib/size failure, scan stopped"
                ));
                // Still fill trailer if available as evidence.
                if info.data.len() >= 20 {
                    let t = info.data.len() - 20;
                    info.stored_trailer = Oid::from_bytes(&info.data[t..]);
                }
                return info;
            }
        }
    }

    if pos + 20 > info.data.len() {
        info.header_issue = Some(format!(
            "pack truncated after object data at offset {pos}: need 20-byte trailer"
        ));
        if info.data.len() >= 20 {
            let t = info.data.len() - 20;
            info.stored_trailer = Oid::from_bytes(&info.data[t..]);
        }
        return info;
    }
    let trailer_at = pos;
    info.stored_trailer = Oid::from_bytes(&info.data[trailer_at..trailer_at + 20]);
    let computed = {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(&info.data[..trailer_at]);
        Oid(h.finalize().into())
    };
    info.computed_trailer = Some(computed);
    if info.stored_trailer != Some(computed) {
        info.header_issue = Some(format!(
            "pack checksum mismatch: stored {} computed {}",
            info.stored_trailer.map(|o| o.short()).unwrap_or_default(),
            computed.short()
        ));
    }
    info
}

/// Convenience error wrapper used by engine/tests.
pub fn delta_parse_err(e: DeltaError) -> String {
    e.to_string()
}
