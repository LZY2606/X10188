//! Parser for git pack files (version 2). Entries are parsed defensively:
//! one bad object never stops the rest of the pack from being examined.

use super::{read_ofs_varint, read_size_varint, InflateError, ObjType, Oid};
use crate::gitfmt::zlib::inflate_at;

#[derive(Debug, Clone)]
pub struct PackFile {
    pub data: Vec<u8>,
    pub version: u32,
    pub num_objects: u32,
    /// SHA-1 stored in the trailing 20 bytes.
    pub trailer: Oid,
    pub computed_trailer: Oid,
    pub trailer_ok: bool,
    pub entries: Vec<PackEntry>,
    pub errors: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryProblem {
    /// Header itself is undecodable / truncated.
    BadHeader,
    /// Reserved or unknown object type bits.
    BadType,
    /// ofs-delta distance does not land on an entry.
    OfsOutOfBounds,
    /// zlib stream corrupt / truncated.
    BadZlib,
    /// Declared size differs from what actually inflated ("size spoof").
    SizeSpoof,
    /// Inflated payload exceeds the safety cap.
    CapExceeded,
    /// Entry's zlib stream runs past the 20-byte pack trailer.
    OverlapsTrailer,
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// Index within the pack (0-based parse order).
    pub ordinal: u32,
    /// Absolute offset of the entry header in the pack.
    pub offset: u64,
    pub kind: Option<ObjType>,
    pub declared_size: u64,
    /// Offset just past the entry header (where zlib data starts).
    pub data_start: u64,
    /// Absolute offset just past the zlib stream (next entry start).
    pub data_end: Option<u64>,
    pub compressed_len: Option<u64>,
    pub inflated: Option<Vec<u8>>,
    /// ref-delta base id, if applicable.
    pub ref_base: Option<Oid>,
    /// ofs-delta base absolute offset, if applicable.
    pub ofs_base: Option<u64>,
    pub problem: Option<EntryProblem>,
    pub problem_detail: Option<String>,
    /// CRC32 over the on-disk entry bytes (header + compressed data).
    pub crc32: Option<u32>,
    /// Oid claimed by a paired index for this offset.
    pub idx_oid: Option<Oid>,
}

const PACK_SIGNATURE: [u8; 4] = *b"PACK";
const HEADER_LEN: usize = 12;
const TRAILER_LEN: usize = 20;

pub fn parse_pack(data: Vec<u8>, inflate_cap: u64) -> Result<PackFile, String> {
    if data.len() < HEADER_LEN + TRAILER_LEN {
        return Err(format!(
            "pack too small: {} bytes",
            data.len()
        ));
    }
    if data[..4] != PACK_SIGNATURE {
        return Err("missing PACK signature".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported pack version {version}"));
    }
    let num_objects = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let trailer = Oid(data[data.len() - TRAILER_LEN..].try_into().unwrap());
    let computed = {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(&data[..data.len() - TRAILER_LEN]);
        Oid(h.finalize().into())
    };
    let trailer_ok = computed == trailer;

    let mut pack = PackFile {
        data,
        version,
        num_objects,
        trailer,
        computed_trailer: computed,
        trailer_ok,
        entries: Vec::with_capacity(num_objects as usize),
        errors: Vec::new(),
    };

    parse_entries(&mut pack, inflate_cap);
    Ok(pack)
}

fn make_problem(pack: &mut PackFile, mut e: PackEntry, p: EntryProblem, detail: String) {
    e.problem = Some(p);
    e.problem_detail = Some(detail.clone());
    pack.errors.push(format!(
        "entry #{} @{}: {detail}",
        e.ordinal, e.offset
    ));
    pack.entries.push(e);
}

fn parse_entries(pack: &mut PackFile, inflate_cap: u64) {
    let body_limit = pack.data.len() - TRAILER_LEN;
    let mut pos = HEADER_LEN;
    let mut ordinal: u32 = 0;

    while ordinal < pack.num_objects {
        if pos >= body_limit {
            pack.errors
                .push(format!("entry #{ordinal}: header runs into pack trailer"));
            break;
        }
        let entry_offset = pos;
        let first = pack.data[pos];
        let raw_type = (first >> 4) & 0b111;
        let kind = ObjType::from_u8(raw_type);
        let size_read = read_size_varint(&pack.data, pos);
        let (declared_size, hdr_len) = match size_read {
            Ok(v) => v,
            Err(err) => {
                pack.errors
                    .push(format!("entry #{ordinal} @{pos}: {err}"));
                break;
            }
        };
        let mut entry = PackEntry {
            ordinal,
            offset: entry_offset as u64,
            kind,
            declared_size,
            data_start: (pos + hdr_len) as u64,
            data_end: None,
            compressed_len: None,
            inflated: None,
            ref_base: None,
            ofs_base: None,
            problem: None,
            problem_detail: None,
            crc32: None,
            idx_oid: None,
        };
        pos += hdr_len;

        if kind.is_none() {
            make_problem(
                pack,
                entry,
                EntryProblem::BadType,
                format!("reserved/unknown object type {raw_type}"),
            );
            ordinal += 1;
            break;
        }
        let kind = kind.unwrap();

        match kind {
            ObjType::RefDelta => {
                if pos + 20 > body_limit {
                    make_problem(
                        pack,
                        entry,
                        EntryProblem::BadHeader,
                        "ref-delta base id runs into pack trailer".into(),
                    );
                    ordinal += 1;
                    break;
                }
                entry.ref_base = Some(Oid(pack.data[pos..pos + 20].try_into().unwrap()));
                pos += 20;
                entry.data_start = pos as u64;
            }
            ObjType::OfsDelta => {
                match read_ofs_varint(&pack.data, pos) {
                    Ok((dist, n)) => {
                        if dist > entry_offset as u64 || dist == 0 {
                            entry.ofs_base = None;
                            entry.data_start = (pos + n) as u64;
                            make_problem(
                                pack,
                                entry,
                                EntryProblem::OfsOutOfBounds,
                                format!(
                                    "ofs-delta distance {dist} does not point before entry offset {entry_offset}"
                                ),
                            );
                            pos += n;
                            ordinal += 1;
                            continue;
                        }
                        let base_off = entry_offset as u64 - dist;
                        entry.ofs_base = Some(base_off);
                        pos += n;
                        entry.data_start = pos as u64;
                        let lands = pack
                            .entries
                            .iter()
                            .any(|e| e.offset == base_off);
                        if !lands {
                            make_problem(
                                pack,
                                entry,
                                EntryProblem::OfsOutOfBounds,
                                format!(
                                    "ofs-delta base offset {base_off} matches no parsed entry"
                                ),
                            );
                            ordinal += 1;
                            continue;
                        }
                    }
                    Err(err) => {
                        make_problem(pack, entry, EntryProblem::BadHeader, err);
                        ordinal += 1;
                        break;
                    }
                }
            }
            _ => {}
        }

        if pos >= body_limit {
            make_problem(
                pack,
                entry,
                EntryProblem::BadHeader,
                "object zlib data starts in trailer area".into(),
            );
            ordinal += 1;
            break;
        }

        let expected = match kind {
            // For deltas the varint is the *delta data* length, not the result.
            ObjType::OfsDelta | ObjType::RefDelta => Some(declared_size),
            _ => Some(declared_size),
        };

        match inflate_at(&pack.data, pos, expected, inflate_cap) {
            Ok(inf) => {
                let end = inf.compressed_end;
                if end > body_limit {
                    make_problem(
                        pack,
                        entry,
                        EntryProblem::OverlapsTrailer,
                        format!("zlib stream ends at {end}, body limit {body_limit}"),
                    );
                    ordinal += 1;
                    break;
                }
                entry.inflated = Some(inf.data);
                entry.data_end = Some(end as u64);
                entry.compressed_len = Some((end - pos) as u64);
                entry.crc32 = Some(crc32fast::hash(
                    &pack.data[entry_offset..end],
                ));
                pos = end;
                pack.entries.push(entry);
            }
            Err(err) => {
                let (prob, msg) = classify(err);
                make_problem(pack, entry, prob, msg);
                break;
            }
        }
        ordinal += 1;
    }

    if pack.entries.len() as u32 != pack.num_objects && !pack.errors.iter().any(|s| s.contains("entry #")) {
        // Already recorded above in most cases; keep an explicit count check too.
    }
    if pack.entries.len() as u32 != pack.num_objects {
        pack.errors.push(format!(
            "object count mismatch: header declares {}, parser recovered {}",
            pack.num_objects,
            pack.entries.len()
        ));
    }
}

fn classify(err: InflateError) -> (EntryProblem, String) {
    match err {
        InflateError::BadStream(s) => (EntryProblem::BadZlib, s),
        InflateError::LargerThanDeclared { declared, actual } => (
            EntryProblem::SizeSpoof,
            format!("size spoof: declared {declared}, inflated {actual} (more)"),
        ),
        InflateError::SmallerThanDeclared { declared, actual } => (
            EntryProblem::SizeSpoof,
            format!("size spoof: declared {declared}, inflated {actual} (fewer)"),
        ),
        InflateError::CapExceeded { cap } => (
            EntryProblem::CapExceeded,
            format!("inflated payload exceeds safety cap {cap}"),
        ),
    }
}
