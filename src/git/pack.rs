//! Git packfile structural parser. It records raw offsets and zlib
//! boundaries for every entry without trusting advertised sizes.

use super::types::{
    decode_ofs_distance, decode_size, oid_hex, ObjType, OID_LEN,
};
use super::zlib::{drain_boundary, crc32, InflateStatus};
use crate::error::{Error, Result};
use sha1::{Digest, Sha1};

pub const PACK_SIGNATURE: [u8; 4] = *b"PACK";
pub const PACK_HEADER_LEN: usize = 12;

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub index: usize,
    pub offset: u64,
    pub kind: ObjType,
    pub claimed_size: u64,
    /// Bytes from entry start up to (and including) compressed data prefix:
    /// header length only (entry start -> first compressed byte).
    pub header_len: usize,
    /// Length of the zlib stream starting at `offset + header_len`.
    pub compressed_len: usize,
    pub inflated_len: u64,
    pub inflate_status: &'static str,
    pub inflate_detail: String,
    /// CRC32 over the whole on-disk entry (header + zlib stream).
    pub entry_crc32: u32,
    pub ofs_base_offset: Option<u64>,
    pub ref_base_oid: Option<[u8; OID_LEN]>,
    /// Oid claimed by a paired index for this entry.
    pub claim_oid: Option<[u8; OID_LEN]>,
    /// CRC the paired index records for this entry.
    pub idx_crc32: Option<u32>,
}

impl PackEntry {
    pub fn data_start(&self) -> u64 {
        self.offset + self.header_len as u64
    }
    pub fn end(&self) -> u64 {
        self.data_start() + self.compressed_len as u64
    }
    pub fn crc_ok(&self) -> Option<bool> {
        self.idx_crc32.map(|c| c == self.entry_crc32)
    }
}

#[derive(Debug, Clone)]
pub struct PackImage {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_offset: u64,
    pub computed_checksum: [u8; OID_LEN],
    pub stored_checksum: [u8; OID_LEN],
    pub checksum_ok: bool,
    pub parse_error: Option<String>,
}

impl PackImage {
    pub fn entry_at(&self, offset: u64) -> Option<&PackEntry> {
        self.entries.binary_search_by_key(&offset, |e| e.offset).ok().map(|i| &self.entries[i])
    }
}

fn status_name(s: &InflateStatus) -> (&'static str, String) {
    match s {
        InflateStatus::Ok => ("ok", String::new()),
        InflateStatus::SizeSpoof { detail } => ("size_spoof", detail.clone()),
        InflateStatus::Truncated => ("truncated", "zlib stream truncated".into()),
        InflateStatus::HardCapExceeded => ("hard_cap", "hard expansion cap exceeded".into()),
        InflateStatus::BudgetPaused { .. } => {
            ("budget_paused", "budget pause during parse drain".into())
        }
    }
}

pub fn parse_pack(data: &[u8]) -> Result<PackImage> {
    if data.len() < PACK_HEADER_LEN + OID_LEN {
        return Err(Error::bad("pack shorter than 32 bytes"));
    }
    if &data[0..4] != PACK_SIGNATURE {
        return Err(Error::parse("missing PACK signature"));
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(Error::parse(format!("unsupported pack version {version}")));
    }
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());

    let trailer_offset = (data.len() - OID_LEN) as u64;
    let stored_checksum: [u8; OID_LEN] = data[data.len() - OID_LEN..].try_into().unwrap();
    let computed = Sha1::digest(&data[..data.len() - OID_LEN]);
    let mut computed_checksum = [0u8; OID_LEN];
    computed_checksum.copy_from_slice(&computed);

    let mut entries: Vec<PackEntry> = Vec::new();
    let mut pos = PACK_HEADER_LEN;
    let mut parse_error: Option<String> = None;

    for index in 0..count as usize {
        if pos >= data.len() - OID_LEN {
            parse_error = Some(format!("entry {index}: header runs past pack body"));
            break;
        }
        let entry_offset = pos as u64;
        let first = data[pos];
        let (size, hn) = decode_size(first, &data[pos + 1..]);
        let kind_code = (first >> 4) & 0x07;
        let kind = match ObjType::from_pack_code(kind_code) {
            Ok(k) => k,
            Err(e) => {
                parse_error = Some(format!("entry {index} @{pos}: {e}"));
                break;
            }
        };
        pos += hn;

        let mut ofs_base_offset = None;
        let mut ref_base_oid = None;

        if kind == ObjType::OfsDelta {
            if pos >= data.len() {
                parse_error = Some(format!("entry {index}: truncated ofs-delta header"));
                break;
            }
            let b0 = data[pos];
            let (dist, dn) = decode_ofs_distance(b0, &data[pos + 1..]);
            pos += dn;
            if dist > entry_offset {
                parse_error = Some(format!(
                    "entry {index} @{}: ofs-delta distance {} points before pack start (base would be {})",
                    entry_offset,
                    dist,
                    entry_offset as i64 - dist as i64
                ));
                break;
            }
            ofs_base_offset = Some(entry_offset - dist);
        } else if kind == ObjType::RefDelta {
            if pos + OID_LEN > data.len() {
                parse_error = Some(format!("entry {index}: truncated ref-delta header"));
                break;
            }
            let mut oid = [0u8; OID_LEN];
            oid.copy_from_slice(&data[pos..pos + OID_LEN]);
            ref_base_oid = Some(oid);
            pos += OID_LEN;
        }

        let header_len = pos - entry_offset as usize;
        let comp = &data[pos..];
        let outcome = drain_boundary(comp, size);
        let (status_name_, detail) = status_name(&outcome.status);

        if outcome.compressed_len == 0 {
            parse_error = Some(format!(
                "entry {index} @{entry_offset}: could not locate zlib boundary ({detail})"
            ));
            break;
        }
        let end = pos + outcome.compressed_len;
        let entry_crc32 = crc32(&data[entry_offset as usize..end]);

        entries.push(PackEntry {
            index,
            offset: entry_offset,
            kind,
            claimed_size: size,
            header_len,
            compressed_len: outcome.compressed_len,
            inflated_len: outcome.actual,
            inflate_status: status_name_,
            inflate_detail: detail,
            entry_crc32,
            ofs_base_offset,
            ref_base_oid,
            claim_oid: None,
            idx_crc32: None,
        });
        pos = end;
    }

    if parse_error.is_none() && pos as u64 != trailer_offset {
        parse_error = Some(format!(
            "entries consume {pos} bytes but pack trailer starts at {trailer_offset} ({} byte{} unaccounted)",
            trailer_offset as i64 - pos as i64,
            if trailer_offset as usize == pos { "" } else { "s" }
        ));
    }

    let checksum_ok = computed_checksum == stored_checksum;
    Ok(PackImage {
        version,
        count,
        entries,
        trailer_offset,
        computed_checksum,
        stored_checksum,
        checksum_ok,
        parse_error,
    })
}

/// Apply index claims (oid + per-entry CRC) onto parsed entries.
pub fn attach_idx(pack: &mut PackImage, idx: &super::idx::IdxImage) {
    for e in pack.entries.iter_mut() {
        if let Some(rec) = idx.record_at(e.offset) {
            e.claim_oid = Some(rec.oid);
            e.idx_crc32 = Some(rec.crc32);
        }
    }
}

pub fn describe_hex(id: &[u8; OID_LEN]) -> String {
    oid_hex(id)
}
