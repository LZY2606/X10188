//! Git v2 pack and index (.idx) parsing, implemented from scratch.

use crate::delta::{read_ofs_delta, read_size_varint};
use crate::gitobj::GitKind;
use crate::oid::Oid;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct PackHeader {
    pub version: u32,
    pub num_objects: u32,
    pub header_offset: usize,
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Absolute offset of the entry header byte inside the pack file.
    pub offset: u64,
    pub kind: GitKind,
    pub declared_size: u64,
    /// Absolute offset where the zlib stream starts.
    pub data_offset: u64,
    /// Delta base: absolute offset (ofs-delta) or oid (ref-delta).
    pub base_ofs: Option<u64>,
    pub base_oid: Option<Oid>,
}

#[derive(Debug, Clone)]
pub struct PackInfo {
    pub source_id: i64,
    pub header: PackHeader,
    pub entries: Vec<PackEntry>,
    /// Range of object data: after header to start of 20-byte trailer.
    pub data_end: usize,
    pub actual_trailer: Oid,
    pub computed_trailer: Oid,
    pub trailer_ok: bool,
    pub errors: Vec<PackError>,
    /// Offsets at which a complete entry header was seen, even if inflate failed.
    pub raw_len: usize,
}

#[derive(Debug, Clone)]
pub enum PackError {
    BadMagic,
    UnsupportedVersion(u32),
    Truncated { at: usize, what: String },
    EntryScan { at: u64, message: String },
    TrailerMismatch { expected: Oid, actual: Oid },
}

impl PackError {
    pub fn message(&self) -> String {
        match self {
            PackError::BadMagic => "missing 'PACK' magic".into(),
            PackError::UnsupportedVersion(v) => format!("unsupported pack version {v}"),
            PackError::Truncated { at, what } => format!("truncated at byte {at}: {what}"),
            PackError::EntryScan { at, message } => format!("entry @{at}: {message}"),
            PackError::TrailerMismatch { expected, actual } => {
                format!("pack checksum mismatch: computed {expected}, stored {actual}")
            }
        }
    }
}

pub const PACK_MAGIC: &[u8; 4] = b"PACK";

fn u32be(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

/// Parse just the 12-byte pack header.
pub fn parse_header(buf: &[u8]) -> Result<PackHeader, PackError> {
    if buf.len() < 12 {
        return Err(PackError::Truncated {
            at: buf.len(),
            what: "pack header needs 12 bytes".into(),
        });
    }
    if &buf[0..4] != PACK_MAGIC {
        return Err(PackError::BadMagic);
    }
    let version = u32be(&buf[4..8]);
    if version != 2 {
        return Err(PackError::UnsupportedVersion(version));
    }
    Ok(PackHeader {
        version,
        num_objects: u32be(&buf[8..12]),
        header_offset: 0,
    })
}

/// Read the per-entry "type + size" header (plus delta base descriptor).
/// Returns the entry and the position at which zlib data begins.
fn read_entry_header(buf: &[u8], offset: usize) -> Result<(PackEntry, usize), String> {
    if offset >= buf.len() {
        return Err("entry offset beyond pack length".into());
    }
    let mut pos = offset;
    let first = buf[pos];
    pos += 1;
    let bits = (first >> 4) & 0x7;
    let kind = GitKind::from_pack_bits(bits);
    let mut size = u64::from(first & 0x0f);
    let mut shift = 4;
    let mut cont = first & 0x80 != 0;
    while cont {
        if pos >= buf.len() {
            return Err("entry size varint truncated".into());
        }
        let b = buf[pos];
        pos += 1;
        size |= u64::from(b & 0x7f) << shift;
        shift += 7;
        cont = b & 0x80 != 0;
    }

    let mut base_ofs = None;
    let mut base_oid = None;
    match kind {
        GitKind::OfsDelta => {
            let rel = read_ofs_delta(buf, &mut pos)?;
            let abs = (offset as u64).checked_sub(rel).ok_or_else(|| {
                format!("ofs-delta distance {rel} underflows entry offset {offset}")
            })?;
            base_ofs = Some(abs);
        }
        GitKind::RefDelta => {
            if pos + 20 > buf.len() {
                return Err("ref-delta base oid truncated".into());
            }
            base_oid = Some(Oid::from_bytes(&buf[pos..pos + 20]).unwrap());
            pos += 20;
        }
        _ => {}
    }

    Ok((
        PackEntry {
            offset: offset as u64,
            kind,
            declared_size: size,
            data_offset: pos as u64,
            base_ofs,
            base_oid,
        },
        pos,
    ))
}

/// Inflate one entry at `data_offset`, enforcing its declared size cap.
pub struct EntryInflate {
    pub data: Vec<u8>,
    pub consumed: usize,
    pub stream_end: bool,
    /// Inflated size differs from the size claimed in the entry header.
    pub size_spoof: bool,
}

pub fn inflate_entry(buf: &[u8], entry: &PackEntry) -> Result<EntryInflate, String> {
    let start = entry.data_offset as usize;
    if start >= buf.len() {
        return Err("zlib start beyond pack".into());
    }
    // Cap declared size, but allow one extra byte so a stream emitting
    // declared+1 is detected as spoof rather than a generic zlib error.
    let cap = entry.declared_size.saturating_add(1) as usize;
    let r = crate::zlib::inflate_bounded(&buf[start..], cap)
        .map_err(|e| format!("inflate failed: {e}"))?;
    let mut spoof = r.limit_hit;
    if r.data.len() as u64 != entry.declared_size {
        spoof = true;
    }
    Ok(EntryInflate {
        data: r.data,
        consumed: r.consumed,
        stream_end: r.stream_end,
        size_spoof: spoof,
    })
}

/// Scan every pack entry sequentially. A corrupted entry that destroys the
/// byte boundary aborts the scan; an .idx can still locate later entries.
pub fn scan_pack(buf: &[u8], source_id: i64) -> PackInfo {
    let mut errors = Vec::new();
    let header = match parse_header(buf) {
        Ok(h) => h,
        Err(e) => {
            let trailer = Oid::ZERO;
            errors.push(e);
            return PackInfo {
                source_id,
                header: PackHeader {
                    version: 0,
                    num_objects: 0,
                    header_offset: 0,
                },
                entries: Vec::new(),
                data_end: buf.len(),
                actual_trailer: trailer,
                computed_trailer: trailer,
                trailer_ok: false,
                errors,
                raw_len: buf.len(),
            };
        }
    };

    let mut entries: Vec<PackEntry> = Vec::with_capacity(header.num_objects as usize);
    let mut pos = 12usize;
    let trailer_start = buf.len().saturating_sub(20);

    while entries.len() < header.num_objects as usize {
        let entry_offset = pos;
        if entry_offset >= trailer_start {
            errors.push(PackError::Truncated {
                at: entry_offset,
                what: format!(
                    "expected {} entries, found {}",
                    header.num_objects,
                    entries.len()
                ),
            });
            break;
        }
        let (entry, header_end) = match read_entry_header(buf, entry_offset) {
            Ok(v) => v,
            Err(message) => {
                errors.push(PackError::EntryScan {
                    at: entry_offset as u64,
                    message,
                });
                break;
            }
        };
        // Inflate solely to find the zlib boundary for the sequential scan.
        match inflate_entry(buf, &entry) {
            Ok(inf) => {
                if !inf.stream_end {
                    errors.push(PackError::EntryScan {
                        at: entry_offset as u64,
                        message: "zlib stream did not end within pack".into(),
                    });
                    break;
                }
                pos = header_end + inf.consumed;
            }
            Err(message) => {
                errors.push(PackError::EntryScan {
                    at: entry_offset as u64,
                    message,
                });
                break;
            }
        }
        entries.push(entry);
    }

    let (actual, computed, ok) = if buf.len() >= 32 {
        let mut h = Sha1::new();
        h.update(&buf[..trailer_start]);
        let computed = Oid(h.finalize().into());
        let actual = Oid::from_bytes(&buf[trailer_start..]).unwrap_or(Oid::ZERO);
        let ok = computed == actual;
        if !ok {
            errors.push(PackError::TrailerMismatch {
                expected: computed,
                actual,
            });
        }
        (actual, computed, ok)
    } else {
        (Oid::ZERO, Oid::ZERO, false)
    };

    PackInfo {
        source_id,
        header,
        entries,
        data_end: trailer_start,
        actual_trailer: actual,
        computed_trailer: computed,
        trailer_ok: ok,
        errors,
        raw_len: buf.len(),
    }
}
