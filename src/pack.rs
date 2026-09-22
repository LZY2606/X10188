//! Parser for Git pack files (v2/v3) and a dependency-free synthetic builder
//! used by tests. Parsing never invokes the system `git`.

use crate::git::{crc32, decode_size, zlib_decode_at, OBJ_OFS_DELTA, OBJ_REF_DELTA};
use sha1::{Digest, Sha1};

/// Hard safety cap for a single inflated object while scanning a pack. This is
/// a parser-level guard, distinct from the analysis budgets.
pub const MAX_INFLATED_PACK_OBJECT: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub kind: u8,
    pub declared_size: u64,
    pub inflated: Vec<u8>,
    pub header_len: usize,
    pub compressed_len: usize,
    pub record_crc: u32,
    pub base_ofs: Option<u64>,
    pub base_ref: Option<[u8; 20]>,
    pub errors: Vec<String>,
}

impl PackEntry {
    pub fn record_end(&self) -> u64 {
        self.offset + self.header_len as u64 + self.compressed_len as u64
    }
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub raw_len: u64,
    pub trailer_sha: [u8; 20],
    pub computed_sha: [u8; 20],
    pub trailer_ok: bool,
    /// Fatal/scan errors: (byte offset, message).
    pub scan_errors: Vec<(u64, String)>,
}

impl ParsedPack {
    pub fn entry_at(&self, ofs: u64) -> Option<&PackEntry> {
        self.entries.iter().find(|e| e.offset == ofs)
    }
}

fn u32be(d: &[u8]) -> u32 {
    u32::from_be_bytes([d[0], d[1], d[2], d[3]])
}

/// Decode a pack entry header at `data[pos]`.
/// Returns (kind, declared_size, header_len, optional_ref, optional_base_ofs_distance).
fn decode_entry_header(
    data: &[u8],
    pos: usize,
) -> Result<(u8, u64, usize, Option<[u8; 20]>, Option<u64>), String> {
    if pos >= data.len() {
        return Err("entry header beyond pack".into());
    }
    let b0 = data[pos];
    let kind = (b0 >> 4) & 0x7;
    if kind == 0 || kind == 5 {
        return Err(format!("invalid/reserved object type {kind}"));
    }
    let mut size = (b0 & 0x0f) as u64;
    let mut shift = 4u32;
    let mut p = pos + 1;
    if b0 & 0x80 != 0 {
        loop {
            if p >= data.len() {
                return Err("truncated entry header".into());
            }
            let b = data[p];
            size |= ((b & 0x7f) as u64) << shift;
            p += 1;
            shift += 7;
            if b & 0x80 == 0 {
                break;
            }
            if shift > 60 {
                return Err("entry size too large".into());
            }
        }
    }
    let mut base_ref = None;
    let mut ofs_distance = None;
    if kind == OBJ_OFS_DELTA {
        let (dist, n) = crate::git::decode_ofs(&data[p..])
            .ok_or_else(|| "truncated ofs-delta offset".to_string())?;
        p += n;
        ofs_distance = Some(dist);
    } else if kind == OBJ_REF_DELTA {
        if p + 20 > data.len() {
            return Err("truncated ref-delta base name".into());
        }
        let mut name = [0u8; 20];
        name.copy_from_slice(&data[p..p + 20]);
        p += 20;
        base_ref = Some(name);
    }
    Ok((kind, size, p - pos, base_ref, ofs_distance))
}

pub fn parse_pack(data: &[u8]) -> ParsedPack {
    let mut pp = ParsedPack {
        version: 0,
        count: 0,
        entries: Vec::new(),
        raw_len: data.len() as u64,
        trailer_sha: [0u8; 20],
        computed_sha: [0u8; 20],
        trailer_ok: false,
        scan_errors: Vec::new(),
    };
    if data.len() < 32 {
        pp.scan_errors
            .push((0, format!("pack too small: {} bytes", data.len())));
        return pp;
    }
    if &data[0..4] != b"PACK" {
        pp.scan_errors.push((0, "missing PACK signature".into()));
        return pp;
    }
    pp.version = u32be(&data[4..8]);
    pp.count = u32be(&data[8..12]);
    if !(2..=3).contains(&pp.version) {
        pp.scan_errors
            .push((4, format!("unsupported pack version {}", pp.version)));
    }
    let body_end = data.len() - 20;
    let mut hasher = Sha1::new();
    hasher.update(&data[..body_end]);
    pp.computed_sha = hasher.finalize().into();
    pp.trailer_sha.copy_from_slice(&data[body_end..]);
    pp.trailer_ok = pp.trailer_sha == pp.computed_sha;
    if !pp.trailer_ok {
        pp.scan_errors.push((
            body_end as u64,
            "pack trailer SHA1 mismatch (corrupt or truncated pack)".into(),
        ));
    }

    let mut pos = 12usize;
    let mut idx = 0u32;
    while pos < body_end && idx < pp.count + 16 {
        let entry_offset = pos as u64;
        let (kind, size, hlen, base_ref, ofs_dist) = match decode_entry_header(data, pos) {
            Ok(v) => v,
            Err(msg) => {
                pp.scan_errors.push((entry_offset, msg));
                break;
            }
        };
        pos += hlen;
        let mut entry = PackEntry {
            offset: entry_offset,
            kind,
            declared_size: size,
            inflated: Vec::new(),
            header_len: hlen,
            compressed_len: 0,
            record_crc: 0,
            base_ofs: None,
            base_ref,
            errors: Vec::new(),
        };
        if let Some(dist) = ofs_dist {
            if dist > entry_offset {
                entry.errors.push(format!(
                    "ofs-delta distance {dist} points before start of pack (entry at {entry_offset})"
                ));
            } else {
                entry.base_ofs = Some(entry_offset - dist);
            }
        }
        if pos >= body_end {
            entry
                .errors
                .push("zlib data missing: entry header reaches pack end".into());
            pp.entries.push(entry);
            pp.scan_errors
                .push((entry_offset, "missing zlib stream".into()));
            break;
        }
        match zlib_decode_at(data, pos, MAX_INFLATED_PACK_OBJECT) {
            Ok(zr) => {
                entry.compressed_len = zr.consumed;
                entry.inflated = zr.data;
                pos += zr.consumed;
                if !zr.clean_end {
                    entry.errors.push("zlib stream did not end cleanly".into());
                }
            }
            Err(e) => {
                entry
                    .errors
                    .push(format!("zlib decompression failed: {e}"));
                pp.entries.push(entry);
                pp.scan_errors.push((
                    entry_offset,
                    format!("cannot continue scan after zlib failure: {e}"),
                ));
                break;
            }
        }
        let record_end = entry.record_end() as usize;
        if record_end <= data.len() {
            entry.record_crc = crc32(&data[entry_offset as usize..record_end]);
        }
        pp.entries.push(entry);
        idx += 1;
    }
    if pp.entries.len() as u32 != pp.count {
        pp.scan_errors.push((
            pos as u64,
            format!(
                "entry count mismatch: header says {} but {} parsed",
                pp.count,
                pp.entries.len()
            ),
        ));
    }
    pp
}

// ---------------------------------------------------------------------------
// Synthetic pack builder (test support; also used to craft corrupt fixtures).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum SynEntry {
    Full { kind: u8, content: Vec<u8> },
    /// Delta against an earlier entry identified by its builder index.
    OfsDelta { base_index: usize, delta: Vec<u8> },
    RefDelta { base: [u8; 20], delta: Vec<u8> },
}

#[derive(Debug, Default, Clone)]
pub struct BuildOptions {
    /// Indices whose declared size in the header will be a wrong value.
    pub spoof_size: Vec<usize>,
    /// Flip one byte in the pack trailer so the checksum fails.
    pub bad_trailer: bool,
    /// Truncate this many bytes off the end (before trailer if possible).
    pub truncate: usize,
}

pub struct BuiltPack {
    pub bytes: Vec<u8>,
    /// Builder-index -> absolute offset in the pack.
    pub offsets: Vec<u64>,
}

fn encode_entry_header(kind: u8, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b0 = (size as u8 & 0x0f) | ((kind & 0x7) << 4);
    let mut rest = size >> 4;
    if rest != 0 {
        b0 |= 0x80;
    }
    out.push(b0);
    while rest != 0 {
        let mut b = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
    out
}

/// Build a pack from full objects and deltas.
pub fn build_pack(entries: &[SynEntry], opts: &BuildOptions) -> BuiltPack {
    let mut out = Vec::new();
    out.extend_from_slice(b"PACK");
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    let mut offsets = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let offset = out.len() as u64;
        offsets.push(offset);
        match e {
            SynEntry::Full { kind, content } => {
                let declared = if opts.spoof_size.contains(&i) {
                    content.len() as u64 + 4096
                } else {
                    content.len() as u64
                };
                out.extend_from_slice(&encode_entry_header(*kind, declared));
                out.extend_from_slice(&crate::git::zlib_encode(content));
            }
            SynEntry::OfsDelta { base_index, delta } => {
                let declared = if opts.spoof_size.contains(&i) {
                    delta.len() as u64 + 999
                } else {
                    delta.len() as u64
                };
                out.extend_from_slice(&encode_entry_header(OBJ_OFS_DELTA, declared));
                let base_offset = offsets[*base_index];
                let distance = offset - base_offset;
                out.extend_from_slice(&crate::git::encode_ofs(distance));
                out.extend_from_slice(&crate::git::zlib_encode(delta));
            }
            SynEntry::RefDelta { base, delta } => {
                let declared = if opts.spoof_size.contains(&i) {
                    delta.len() as u64 + 7
                } else {
                    delta.len() as u64
                };
                out.extend_from_slice(&encode_entry_header(OBJ_REF_DELTA, declared));
                out.extend_from_slice(base);
                out.extend_from_slice(&crate::git::zlib_encode(delta));
            }
        }
    }

    // Truncate body bytes before appending trailer if requested.
    let mut truncate = opts.truncate;
    if truncate > 0 {
        if truncate >= out.len() {
            out.clear();
        } else {
            out.truncate(out.len() - truncate);
        }
        truncate = 0;
    }

    let mut hasher = Sha1::new();
    hasher.update(&out);
    let mut sum: [u8; 20] = hasher.finalize().into();
    if opts.bad_trailer {
        sum[0] ^= 0xff;
    }
    out.extend_from_slice(&sum);
    let _ = truncate;
    BuiltPack { bytes: out, offsets }
}

/// Build a v2 index for a pack. `mapping` maps entry offset -> (oid, crc32).
/// oid may be forced to an arbitrary value (used for duplicate / mismatch
/// fixtures); supply the real object id for honest indexes.
pub struct IdxRow {
    pub offset: u64,
    pub oid: [u8; 20],
    pub crc: u32,
}

#[derive(Default)]
pub struct IdxOptions {
    /// When true, corrupt the idx's own trailing SHA1 checksum.
    pub bad_idx_checksum: bool,
    /// When true, corrupt the pack checksum stored inside the idx.
    pub bad_pack_checksum: bool,
}

pub fn build_idx_v2(pack: &[u8], rows: &[IdxRow], opts: &IdxOptions) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0xff, 0x74, 0x4f, 0x63]); // \377tOc
    out.extend_from_slice(&2u32.to_be_bytes());

    let n = rows.len();
    // fanout
    let mut sorted: Vec<&IdxRow> = rows.iter().collect();
    sorted.sort_by(|a, b| a.oid.cmp(&b.oid));
    let mut counts = [0u32; 256];
    for r in &sorted {
        counts[r.oid[0] as usize] += 1;
    }
    let mut acc = 0u32;
    for c in counts.iter_mut() {
        acc += *c;
        *c = acc;
    }
    for c in counts {
        out.extend_from_slice(&c.to_be_bytes());
    }
    // sha table
    for r in &sorted {
        out.extend_from_slice(&r.oid);
    }
    // crc table
    for r in &sorted {
        out.extend_from_slice(&r.crc.to_be_bytes());
    }
    // offset table (64-bit offsets not needed for small fixtures)
    for r in &sorted {
        out.extend_from_slice(&(r.offset as u32).to_be_bytes());
    }
    // no 8-byte offset table, no extensions

    let pack_checksum: [u8; 20] = pack[pack.len() - 20..].try_into().unwrap();
    let mut stored_pack = pack_checksum;
    if opts.bad_pack_checksum {
        stored_pack[0] ^= 0x01;
    }
    // The idx checksum covers everything up to and including the pack
    // checksum (i.e. all but the final 20 bytes).
    out.extend_from_slice(&stored_pack);
    let mut h = Sha1::new();
    h.update(&out[..]);
    let mut idx_sum: [u8; 20] = h.finalize().into();
    if opts.bad_idx_checksum {
        idx_sum[0] ^= 0x01;
    }
    out.extend_from_slice(&idx_sum);
    let _ = n;
    out
}

// Kept to avoid an unused warning in some feature combos.
#[allow(dead_code)]
fn ensure_decode_size_link() -> Option<(u64, usize)> {
    decode_size(&[0])
}
