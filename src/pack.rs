//! Parse pack files (`.pack`) and pack index files (`.idx`), retaining raw
//! offsets, CRC32 over each object record and zlib stream boundaries.

use crate::error::Result;
use crate::git::{crc32, decode_ofs_delta, decode_pack_header, inflate_stream, Crc32};
use crate::sha::sha1;
use crate::types::{hex_val, ObjType, Oid20};

pub const PACK_SIG: &[u8; 4] = b"PACK";
pub const IDX_SIG: &[u8; 4] = b"\xfftOc";

#[derive(Clone, Debug)]
pub struct PackObject {
    /// Absolute offset of the object header within the pack file.
    pub offset: u64,
    pub type_id: u8,
    pub typ: ObjType,
    /// Declared inflated size from the pack header.
    pub declared_size: u64,
    pub header_len: usize,
    pub ofs_negative: Option<u64>,
    pub ref_base: Option<Oid20>,
    /// Length of the header including delta base pointer.
    pub pre_zlib_len: usize,
    /// Actual inflated bytes.
    pub inflated: Vec<u8>,
    /// Exact compressed (zlib) record length — the zlib boundary.
    pub zlib_len: usize,
    pub record_crc: u32,
    pub parse_error: Option<String>,
}

#[derive(Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub objects: Vec<PackObject>,
    /// SHA1 over the whole pack file as declared in its 20-byte trailer.
    pub declared_pack_sha: Oid20,
    pub computed_pack_sha: Oid20,
    pub trailer_ok: bool,
    pub error: Option<String>,
}

pub fn parse_pack(data: &[u8]) -> Result<ParsedPack> {
    if data.len() < 32 {
        return Err("pack file shorter than 32-byte envelope".into());
    }
    if &data[..4] != PACK_SIG {
        return Err("bad pack signature".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if !(2..=4).contains(&version) {
        return Err(format!("unsupported pack version {version}"));
    }
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap()) as usize;
    let body_end = data.len() - 20;
    let declared_pack_sha: Oid20 = data[body_end..].try_into().unwrap();
    let computed_pack_sha = sha1(&data[..body_end]);
    let trailer_ok = declared_pack_sha == computed_pack_sha;

    let mut objects = Vec::with_capacity(count);
    let mut pos = 12usize;
    let mut fatal: Option<String> = None;

    for _ in 0..count {
        let offset = pos as u64;
        let mut obj = PackObject {
            offset,
            type_id: 0,
            typ: ObjType::Blob,
            declared_size: 0,
            header_len: 0,
            ofs_negative: None,
            ref_base: None,
            pre_zlib_len: 0,
            inflated: Vec::new(),
            zlib_len: 0,
            record_crc: 0,
            parse_error: None,
        };
        let mut crc = Crc32::new();

        let hdr = match decode_pack_header(&data[pos..]) {
            Ok(h) => h,
            Err(e) => {
                obj.parse_error = Some(format!("header: {e}"));
                fatal = Some(format!("object at {offset}: {e}"));
                objects.push(obj);
                break;
            }
        };
        let (type_id, size, hlen) = hdr;
        obj.type_id = type_id;
        obj.declared_size = size;
        obj.header_len = hlen;
        obj.typ = match ObjType::from_type_id(type_id) {
            Some(t) => t,
            None => {
                obj.parse_error = Some(format!("unknown object type {type_id}"));
                fatal = Some(format!("object at {offset}: unknown type {type_id}"));
                crc.update(&data[pos..pos + hlen]);
                pos += hlen;
                objects.push(obj);
                break;
            }
        };
        crc.update(&data[pos..pos + hlen]);
        pos += hlen;

        match obj.typ {
            ObjType::OfsDelta => match decode_ofs_delta(&data[pos..]) {
                Ok((neg, olen)) => {
                    obj.ofs_negative = Some(neg);
                    obj.pre_zlib_len = pos + olen;
                    crc.update(&data[pos..pos + olen]);
                    pos += olen;
                }
                Err(e) => {
                    obj.parse_error = Some(format!("ofs-delta: {e}"));
                    fatal = Some(format!("object at {offset}: {e}"));
                    objects.push(obj);
                    break;
                }
            },
            ObjType::RefDelta => {
                if pos + 20 > body_end {
                    obj.parse_error = Some("ref-delta base name truncated".into());
                    fatal = Some(format!("object at {offset}: ref-delta base name truncated"));
                    objects.push(obj);
                    break;
                }
                let base: Oid20 = data[pos..pos + 20].try_into().unwrap();
                obj.ref_base = Some(base);
                obj.pre_zlib_len = pos + 20;
                crc.update(&data[pos..pos + 20]);
                pos += 20;
            }
            _ => {
                obj.pre_zlib_len = pos;
            }
        }

        // Inflate exactly one zlib stream; a stream that corrupts or truncates
        // halfway is isolated to this object (decompression-then-fail evidence).
        let z_start = pos;
        match inflate_stream(&data[pos..body_end]) {
            Ok(inf) => {
                obj.inflated = inf.out;
                obj.zlib_len = inf.consumed;
                crc.update(&data[z_start..z_start + inf.consumed]);
                pos += inf.consumed;
            }
            Err(e) => {
                let avail = body_end.saturating_sub(pos);
                crc.update(&data[pos..body_end]);
                obj.record_crc = crc.finish();
                obj.parse_error =
                    Some(format!("zlib failed halfway after {avail} compressed bytes: {e}"));
                objects.push(obj);
                fatal = Some(format!("object at {offset}: zlib stream corrupt, cannot locate next object"));
                break;
            }
        }
        obj.record_crc = crc.finish();
        objects.push(obj);
    }

    Ok(ParsedPack {
        version,
        objects,
        declared_pack_sha,
        computed_pack_sha,
        trailer_ok,
        error: fatal,
    })
}

#[derive(Clone, Debug)]
pub struct IdxEntry {
    pub offset: u64,
    pub oid: Oid20,
    /// Present in v2 only; None for v1.
    pub crc32: Option<u32>,
}

#[derive(Debug)]
pub struct ParsedIdx {
    pub version: u32,
    /// Raw 256-entry fanout table (cumulative counts).
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    /// v2: SHA1 of the pack this index claims to describe.
    pub pack_sha: Oid20,
    /// v2: SHA1 trailer of the index file itself.
    pub index_sha: Oid20,
    pub computed_index_sha: Oid20,
    pub index_sha_ok: bool,
    pub error: Option<String>,
}

fn read_u32(data: &[u8], at: usize) -> Result<u32> {
    data.get(at..at + 4)
        .map(|s| u32::from_be_bytes(s.try_into().unwrap()))
        .ok_or_else(|| "index truncated".into())
}

pub fn parse_idx(data: &[u8]) -> Result<ParsedIdx> {
    if data.len() < 8 {
        return Err("index too short".into());
    }
    let mut fanout = [0u32; 256];

    if &data[..4] == IDX_SIG {
        let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if version != 2 {
            return Err(format!("unsupported idx version {version}"));
        }
        if data.len() < 8 + 256 * 4 {
            return Err("idx v2 fanout truncated".into());
        }
        for i in 0..256 {
            fanout[i] = u32::from_be_bytes(data[8 + i * 4..12 + i * 4].try_into().unwrap());
        }
        let n = fanout[255] as usize;
        let mut p = 8 + 256 * 4;
        let need = p + n * 20 + n * 4 + n * 24 + 40;
        if data.len() < need {
            return Err("idx v2 tables truncated".into());
        }
        let name_base = p;
        let crc_base = name_base + n * 20;
        let off_base = crc_base + n * 4;
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            let oid: Oid20 = data[name_base + i * 20..name_base + i * 20 + 20]
                .try_into()
                .unwrap();
            let crc = u32::from_be_bytes(
                data[crc_base + i * 4..crc_base + i * 4 + 4].try_into().unwrap(),
            );
            let off_word = u32::from_be_bytes(
                data[off_base + i * 4..off_base + i * 4 + 4].try_into().unwrap(),
            );
            let offset = if off_word & 0x8000_0000 != 0 {
                let idx = (off_word & 0x7fff_ffff) as usize;
                let l64_base = off_base + n * 4;
                let at = l64_base + idx * 8;
                u64::from_be_bytes(data[at..at + 8].try_into().unwrap())
            } else {
                off_word as u64
            };
            entries.push(IdxEntry {
                offset,
                oid,
                crc32: Some(crc),
            });
        }
        let trailer_off = off_base + n * 4;
        let pack_sha: Oid20 = data[trailer_off..trailer_off + 20].try_into().unwrap();
        let index_sha: Oid20 = data[trailer_off + 20..trailer_off + 40].try_into().unwrap();
        let computed_index_sha = sha1(&data[..trailer_off + 20]);
        Ok(ParsedIdx {
            version: 2,
            fanout,
            entries,
            pack_sha,
            index_sha,
            computed_index_sha,
            index_sha_ok: computed_index_sha == index_sha,
            error: None,
        })
    } else {
        // v1: 256 fanout words, then (offset u32 BE, name 20) records.
        if data.len() < 256 * 4 {
            return Err("idx v1 fanout truncated".into());
        }
        for i in 0..256 {
            fanout[i] = u32::from_be_bytes(data[i * 4..i * 4 + 4].try_into().unwrap());
        }
        let n = fanout[255] as usize;
        let mut p = 256 * 4;
        let need = p + n * 24 + 40;
        if data.len() < need {
            return Err("idx v1 records truncated".into());
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let offset = u32::from_be_bytes(data[p..p + 4].try_into().unwrap()) as u64;
            p += 4;
            let oid: Oid20 = data[p..p + 20].try_into().unwrap();
            p += 20;
            entries.push(IdxEntry {
                offset,
                oid,
                crc32: None,
            });
        }
        let pack_sha: Oid20 = data[p..p + 20].try_into().unwrap();
        let index_sha = [0u8; 20];
        Ok(ParsedIdx {
            version: 1,
            fanout,
            entries,
            pack_sha,
            index_sha,
            computed_index_sha: [0u8; 20],
            index_sha_ok: true,
            error: None,
        })
    }
}

/// CRC32 git stores in idx v2 covers the packed object record starting at its
/// header byte (type/size, optional delta base, zlib-compressed payload).
pub fn record_crc(data: &[u8]) -> u32 {
    crc32(data)
}

#[allow(dead_code)]
fn use_hex_val(b: u8) -> Option<u8> {
    hex_val(b)
}
