// Low-level, dependency-free parsing of Git pack / idx / loose-object bytes.
// No external `git` binary is invoked anywhere in this crate.

use flate2::{Decompress, FlushDecompress};
use sha1::{Digest, Sha1};

pub const OID_LEN: usize = 20;
pub const PACK_SIG: [u8; 4] = *b"PACK";
pub const IDX_SIG: [u8; 4] = [255, 116, 79, 99];

pub type Oid = [u8; 20];

pub fn hex_oid(o: &Oid) -> String {
    hex::encode(o)
}

pub fn parse_oid(s: &str) -> Option<Oid> {
    let v = hex::decode(s.trim()).ok()?;
    if v.len() != OID_LEN {
        return None;
    }
    let mut o = [0u8; OID_LEN];
    o.copy_from_slice(&v);
    Some(o)
}

pub fn git_object_id(kind: &str, data: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(kind.as_bytes());
    h.update(b" ");
    h.update(data.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(data);
    let mut o = [0u8; OID_LEN];
    o.copy_from_slice(&h.finalize());
    o
}

#[derive(Debug, Clone)]
pub enum FmtError {
    Msg(String),
}

impl std::fmt::Display for FmtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FmtError::Msg(s) => f.write_str(s),
        }
    }
}
impl std::error::Error for FmtError {}

pub fn ferr(s: impl Into<String>) -> FmtError {
    FmtError::Msg(s.into())
}

// ---------- CRC32 (zlib/IEEE polynomial), matching Git's hashcpy trailer ----------

pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xed_b8_83_20 & mask);
        }
    }
    !crc
}

// ---------- size/varint encoding used by pack entries ----------

pub fn read_size_varint(buf: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let mut shift = 0u32;
    let mut size: u64 = 0;
    loop {
        if pos >= buf.len() {
            return None;
        }
        let b = buf[pos];
        pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    Some((size, pos))
}

pub fn write_size_varint(mut size: u64, first_byte_type: Option<u8>) -> Vec<u8> {
    // first_byte_type packs 3 type bits at bits 4..6 and continuation at bit 7.
    let mut out = Vec::new();
    let mut first = true;
    loop {
        let mut b = (size & 0x7f) as u8;
        size >>= 7;
        if first {
            if let Some(t) = first_byte_type {
                b |= (t & 0x07) << 4;
            }
            first = false;
        }
        if size > 0 {
            b |= 0x80;
        }
        out.push(b);
        if size == 0 {
            break;
        }
    }
    out
}

// Git's negative-relative-offset encoding used by OFS_DELTA entries.
pub fn read_ofs_delta_distance(buf: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    if pos >= buf.len() {
        return None;
    }
    let mut b = buf[pos];
    pos += 1;
    let mut dist = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        if pos >= buf.len() {
            return None;
        }
        b = buf[pos];
        pos += 1;
        dist += 1;
        dist <<= 7;
        dist |= (b & 0x7f) as u64;
    }
    Some((dist, pos))
}

pub fn write_ofs_delta_distance(mut dist: u64) -> Vec<u8> {
    let mut bytes = vec![(dist & 0x7f) as u8];
    dist >>= 7;
    while dist > 0 {
        dist -= 1;
        bytes.push(0x80 | ((dist & 0x7f) as u8));
        dist >>= 7;
    }
    bytes.reverse();
    bytes
}

// ---------- zlib boundary-aware inflate ----------

pub struct InflateOutcome {
    pub data: Vec<u8>,
    pub consumed: usize, // exact bytes of the zlib stream inside the source
}

pub fn inflate_boundary(src: &[u8], start: usize, max_out: usize) -> Result<InflateOutcome, String> {
    let mut dec = Decompress::new(true);
    let mut out = Vec::new();
    let mut in_pos = start;
    let chunk = 16 * 1024;
    loop {
        let avail_in = std::cmp::min(chunk, src.len() - in_pos);
        if avail_in == 0 && !dec.is_finished() {
            return Err("zlib stream truncated (no more input)".to_string());
        }
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let mut tmp = vec![0u8; chunk];
        let in_slice = &src[in_pos..in_pos + avail_in];
        let res = dec
            .inflate(in_slice, &mut tmp, FlushDecompress::None)
            .map_err(|e| format!("zlib error: {e}"))?;
        let used_in = (dec.total_in() - before_in) as usize;
        let got_out = (dec.total_out() - before_out) as usize;
        in_pos += used_in;
        out.extend_from_slice(&tmp[..got_out]);
        if out.len() > max_out {
            return Err(format!(
                "declared/actual size deceit: decompressed past {max_out} bytes"
            ));
        }
        let _ = res;
        if got_out == 0 && used_in == 0 {
            return Err("zlib stalled".to_string());
        }
        if dec.is_finished() {
            // Any bytes the decoder did not consume belong to the next object.
            let _ = dec;
            return Ok(InflateOutcome {
                data: out,
                consumed: in_pos,
            });
        }
    }
}


// ---------- object types ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(c: u8) -> Option<ObjType> {
        Some(match c {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            6 => ObjType::OfsDelta,
            7 => ObjType::RefDelta,
            _ => return None,
        })
    }
    pub fn code(self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
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
    pub fn base_type_name(self) -> Option<&'static str> {
        match self {
            ObjType::Commit => Some("commit"),
            ObjType::Tree => Some("tree"),
            ObjType::Blob => Some("blob"),
            ObjType::Tag => Some("tag"),
            _ => None,
        }
    }
}

// ---------- pack structures ----------

#[derive(Debug, Clone)]
pub struct PackHeader {
    pub version: u32,
    pub count: u32,
}

#[derive(Debug, Clone)]
pub enum DeltaRef {
    Ofs { neg_distance: u64, target_offset: Option<u64> },
    Ref { base_oid: Oid },
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub header_len: usize, // bytes consumed by the entry header (type/size + delta ref)
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub delta: Option<DeltaRef>,
    pub zlib_start: usize,
    pub zlib_consumed: Option<usize>, // exact stream length, when boundary known
    pub inflated: Option<Vec<u8>>,
    pub crc_expected: Option<u32>,    // from matching idx
    pub crc_actual: Option<u32>,
    pub crc_ok: Option<bool>,
    pub size_deceit: bool,
    pub parse_error: Option<String>, // per-entry isolation: entry still recorded
}

#[derive(Debug, Clone)]
pub struct PackSummary {
    pub header: PackHeader,
    pub entries: Vec<PackEntry>,
    pub trailer_offset: Option<u64>,
    pub trailer_actual: Option<Oid>,
    pub trailer_ok: Option<bool>,
    pub errors: Vec<String>,
}

// ---------- pack parsing ----------

pub fn parse_pack(buf: &[u8], idx: Option<&IndexSummary>) -> Result<PackSummary, String> {
    let mut errors = Vec::new();
    if buf.len() < 12 + 20 {
        return Err("pack too small for header + SHA1 trailer".to_string());
    }
    if &buf[0..4] != PACK_SIG {
        return Err("bad PACK signature".to_string());
    }
    let version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported pack version {version}"));
    }
    let count = u32::from_be_bytes(buf[8..12].try_into().unwrap());

    // Expected trailer SHA1 covers bytes [0 .. len-20].
    let trailer_offset = (buf.len() - 20) as u64;
    let trailer_actual: Oid = buf[buf.len() - 20..].try_into().unwrap();
    let trailer_calc = {
        let mut h = Sha1::new();
        h.update(&buf[..buf.len() - 20]);
        let mut o = [0u8; 20];
        o.copy_from_slice(&h.finalize());
        o
    };
    let trailer_ok = trailer_actual == trailer_calc;

    let crc_by_offset: std::collections::HashMap<u64, u32> = match idx {
        Some(ix) if ix.trailer_ok.unwrap_or(false) => ix
            .records
            .iter()
            .filter_map(|r| r.offset.map(|o| (o, r.crc32)))
            .collect(),
        _ => std::collections::HashMap::new(),
    };

    let mut entries = Vec::new();
    let mut pos = 12usize;
    for _ in 0..count {
        let entry_offset = pos as u64;
        let entry = parse_pack_entry(buf, &mut pos, entry_offset, &crc_by_offset, &mut errors);
        entries.push(entry);
        if pos >= buf.len() - 20 {
            break;
        }
    }

    if entries.len() as u32 != count {
        errors.push(format!(
            "declared {} objects but only parsed {}",
            count,
            entries.len()
        ));
    }

    Ok(PackSummary {
        header: PackHeader { version, count },
        entries,
        trailer_offset: Some(trailer_offset),
        trailer_actual: Some(trailer_actual),
        trailer_ok: Some(trailer_ok),
        errors,
    })
}

fn parse_pack_entry(
    buf: &[u8],
    pos: &mut usize,
    entry_offset: u64,
    crc_by_offset: &std::collections::HashMap<u64, u32>,
    errors: &mut Vec<String>,
) -> PackEntry {
    let start = *pos;
    let mut ent = PackEntry {
        offset: entry_offset,
        header_len: 0,
        obj_type: ObjType::Blob,
        declared_size: 0,
        delta: None,
        zlib_start: 0,
        zlib_consumed: None,
        inflated: None,
        crc_expected: None,
        crc_actual: None,
        crc_ok: None,
        size_deceit: false,
        parse_error: None,
    };

    if start >= buf.len() - 20 {
        ent.parse_error = Some("entry header beyond pack data".to_string());
        return ent;
    }
    let first = buf[start];
    let type_code = (first >> 4) & 0x07;
    let obj_type = match ObjType::from_code(type_code) {
        Some(t) => t,
        None => {
            *pos = start + 1;
            ent.obj_type = ObjType::Blob;
            ent.parse_error = Some(format!("invalid object type code {type_code}"));
            errors.push(format!("entry @{}: invalid type {}", entry_offset, type_code));
            return ent;
        }
    };
    ent.obj_type = obj_type;

    // First byte: bit7 continuation, bits4-6 type, bits0-3 = size bits 0-3.
    let mut size: u64 = (buf[start] & 0x0f) as u64;
    let mut hp = start + 1;
    let mut shift = 4u32;
    if buf[start] & 0x80 != 0 {
        loop {
            if hp >= buf.len() - 20 {
                ent.parse_error = Some("truncated size varint".to_string());
                *pos = hp;
                return ent;
            }
            let b = buf[hp];
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
            hp += 1;
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    ent.declared_size = size;


    match obj_type {
        ObjType::OfsDelta => match read_ofs_delta_distance(buf, hp) {
            Some((dist, nhp)) => {
                hp = nhp;
                let target = entry_offset.checked_sub(dist);
                ent.delta = Some(DeltaRef::Ofs {
                    neg_distance: dist,
                    target_offset: target,
                });
                if target.is_none() {
                    ent.parse_error = Some(format!(
                        "ofs-delta distance {} underflows entry offset {}",
                        dist, entry_offset
                    ));
                }
            }
            None => {
                ent.parse_error = Some("truncated ofs-delta distance".to_string());
            }
        },
        ObjType::RefDelta => {
            if hp + 20 > buf.len() {
                ent.parse_error = Some("truncated ref-delta base oid".to_string());
            } else {
                let mut oid = [0u8; 20];
                oid.copy_from_slice(&buf[hp..hp + 20]);
                hp += 20;
                ent.delta = Some(DeltaRef::Ref { base_oid: oid });
            }
        }
        _ => {}
    }

    ent.header_len = hp - start;
    ent.zlib_start = hp;
    *pos = hp;

    // Boundary-aware inflate. Max output is bounded generously so that a
    // mid-stream size deceit is detected rather than OOMing the process.
    let max_out = (size.max(64 * 1024) as usize).saturating_mul(64).max(4 * 1024 * 1024);
    match inflate_boundary(buf, hp, max_out) {
        Ok(io) => {
            ent.zlib_consumed = Some(io.consumed - hp);
            let actual = io.data.len() as u64;
            if actual != size {
                ent.size_deceit = true;
                ent.parse_error = Some(format!(
                    "size deceit: header declares {size} but zlib yielded {actual}"
                ));
                errors.push(format!(
                    "entry @{}: size deceit (declared {size}, got {actual})",
                    entry_offset
                ));
            }
            ent.inflated = Some(io.data);
            *pos = io.consumed;
        }
        Err(e) => {
            ent.parse_error = Some(e.clone());
            errors.push(format!("entry @{}: {e}", entry_offset));
            // Cannot reliably continue scanning; clamp at trailer boundary.
            *pos = buf.len() - 20;
            return finalize_crc(ent, buf, crc_by_offset);
        }
    }

    finalize_crc(ent, buf, crc_by_offset)
}

fn finalize_crc(
    mut ent: PackEntry,
    buf: &[u8],
    crc_by_offset: &std::collections::HashMap<u64, u32>,
) -> PackEntry {
    if let Some(&expected) = crc_by_offset.get(&ent.offset) {
        ent.crc_expected = Some(expected);
        if let Some(zlen) = ent.zlib_consumed {
            let end = (ent.zlib_start + zlen).min(buf.len());
            ent.crc_actual = Some(crc32_ieee(&buf[ent.zlib_start..end]));
            ent.crc_ok = Some(ent.crc_actual == Some(expected));
        }
    }
    ent
}

// ---------- index parsing ----------

#[derive(Debug, Clone)]
pub struct IndexRecord {
    pub oid: Oid,
    pub offset: Option<u64>, // None => 64-bit large offset table reference index
    pub large_offset_idx: Option<u64>,
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct IndexSummary {
    pub version: u32, // 1 or 2
    pub fanout: Vec<u32>,
    pub records: Vec<IndexRecord>,
    pub pack_checksum: Option<Oid>,
    pub idx_checksum_actual: Option<Oid>,
    pub trailer_ok: Option<bool>, // idx self checksum
    pub pack_checksum_ok: Option<bool>,
    pub errors: Vec<String>,
}

pub fn parse_index(buf: &[u8]) -> Result<IndexSummary, String> {
    if buf.len() < 8 {
        return Err("idx too small".to_string());
    }
    let v2 = &buf[0..4] == &IDX_SIG;
    if v2 {
        parse_index_v2(buf)
    } else {
        parse_index_v1(buf)
    }
}

fn checksum_idx(buf: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(&buf[..buf.len() - 20]);
    let mut o = [0u8; 20];
    o.copy_from_slice(&h.finalize());
    o
}

fn parse_index_v2(buf: &[u8]) -> Result<IndexSummary, String> {
    let mut errors = Vec::new();
    let version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported idx version {version}"));
    }
    // fanout table: 256 * 4 bytes starting at 8
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        let p = 8 + i * 4;
        fanout.push(u32::from_be_bytes(buf[p..p + 4].try_into().unwrap()));
    }
    let n = *fanout.last().unwrap() as usize;
    let mut p = 8 + 256 * 4;

    let need = |at: usize, l: usize| -> Result<(), String> {
        if at + l > buf.len() - 40 {
            Err("idx truncated: tables shorter than fanout claims".to_string())
        } else {
            Ok(())
        }
    };

    need(p, n * 20)?;
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        let mut o = [0u8; 20];
        o.copy_from_slice(&buf[p..p + 20]);
        p += 20;
        oids.push(o);
    }
    need(p, n * 4)?;
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        crcs.push(u32::from_be_bytes(buf[p..p + 4].try_into().unwrap()));
        p += 4;
    }
    let offsets_start = p;
    need(p, n * 4)?;
    let mut raw_offsets = Vec::with_capacity(n);
    for i in 0..n {
        let q = offsets_start + i * 4;
        raw_offsets.push(u32::from_be_bytes(buf[q..q + 4].try_into().unwrap()));
    }
    p += n * 4;

    // 64-bit offset table: present when offsets were >= 2^31.
    let large_count = if p + 40 <= buf.len() {
        (buf.len() - 40 - p) / 8
    } else {
        0
    };
    let mut records = Vec::with_capacity(n);
    for i in 0..n {
        let raw = raw_offsets[i];
        let (offset, large_idx) = if raw & 0x8000_0000 != 0 {
            let li = (raw & 0x7fff_ffff) as usize;
            if li >= large_count || p + li * 8 + 8 > buf.len() - 40 {
                errors.push(format!("oid {}: large-offset table index {li} OOB", hex::encode(oids[i])));
                (None, Some(li as u64))
            } else {
                let off = u64::from_be_bytes(buf[p + li * 8..p + li * 8 + 8].try_into().unwrap());
                (Some(off), Some(li as u64))
            }
        } else {
            (Some(raw as u64), None)
        };
        records.push(IndexRecord {
            oid: oids[i],
            offset,
            large_offset_idx: large_idx,
            crc32: crcs[i],
        });
    }

    let total = buf.len();
    let idx_checksum_actual = checksum_idx(buf);
    let idx_trailer: Oid = buf[total - 20..total].try_into().unwrap();
    let trailer_ok = idx_checksum_actual == idx_trailer;
    let pack_checksum: Oid = buf[total - 40..total - 20].try_into().unwrap();

    Ok(IndexSummary {
        version: 2,
        fanout,
        records,
        pack_checksum: Some(pack_checksum),
        idx_checksum_actual: Some(idx_checksum_actual),
        trailer_ok: Some(trailer_ok),
        pack_checksum_ok: None,
        errors,
    })
}

fn parse_index_v1(buf: &[u8]) -> Result<IndexSummary, String> {
    // v1: sorted sequence of [u32 offset][20-byte oid], then 20-byte
    // pack checksum, 20-byte idx checksum. No CRC table.
    if buf.len() < 40 {
        return Err("idx v1 too small".to_string());
    }
    let n = (buf.len() - 40) / 24;
    if n * 24 + 40 != buf.len() {
        return Err("idx v1 length not a multiple of 24 plus trailer".to_string());
    }
    let mut records = Vec::with_capacity(n);
    let mut fanout = vec![0u32; 256];
    for i in 0..n {
        let p = i * 24;
        let offset = u32::from_be_bytes(buf[p..p + 4].try_into().unwrap()) as u64;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&buf[p + 4..p + 24]);
        records.push(IndexRecord {
            oid,
            offset: Some(offset),
            large_offset_idx: None,
            crc32: 0,
        });
        fanout[oid[0] as usize] += 1;
    }
    let mut acc = 0u32;
    for v in fanout.iter_mut() {
        acc += *v;
        *v = acc;
    }
    let idx_checksum_actual = checksum_idx(buf);
    let idx_trailer: Oid = buf[buf.len() - 20..].try_into().unwrap();
    let pack_checksum: Oid = buf[buf.len() - 40..buf.len() - 20].try_into().unwrap();
    Ok(IndexSummary {
        version: 1,
        fanout,
        records,
        pack_checksum: Some(pack_checksum),
        idx_checksum_actual: Some(idx_checksum_actual),
        trailer_ok: Some(idx_checksum_actual == idx_trailer),
        pack_checksum_ok: None,
        errors: Vec::new(),
    })
}

// ---------- loose objects ----------

#[derive(Debug, Clone)]
pub struct LooseSummary {
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub data: Vec<u8>,
    pub zlib_consumed: usize,
    pub size_deceit: bool,
    pub oid_by_content: Oid,
    pub content_ok: bool, // content hash matches expected filename, when known
    pub parse_error: Option<String>,
}

pub fn parse_loose(buf: &[u8], expected_oid: Option<&Oid>) -> LooseSummary {
    let mut l = LooseSummary {
        obj_type: ObjType::Blob,
        declared_size: 0,
        data: Vec::new(),
        zlib_consumed: 0,
        size_deceit: false,
        oid_by_content: [0u8; 20],
        content_ok: false,
        parse_error: None,
    };
    match inflate_boundary(buf, 0, 1024 * 1024 * 1024) {
        Ok(io) => {
            l.zlib_consumed = io.consumed;
            let d = io.data;
            let nul = match d.iter().position(|&b| b == 0) {
                Some(i) => i,
                None => {
                    l.parse_error = Some("loose object missing NUL header".to_string());
                    l.data = d;
                    return l;
                }
            };
            let header = match std::str::from_utf8(&d[..nul]) {
                Ok(s) => s,
                Err(_) => {
                    l.parse_error = Some("loose header not utf8".to_string());
                    l.data = d;
                    return l;
                }
            };
            let mut sp = header.split(' ');
            let tn = sp.next().unwrap_or("");
            let sz: u64 = sp.next().and_then(|x| x.parse().ok()).unwrap_or(0);
            let ty = match tn {
                "commit" => ObjType::Commit,
                "tree" => ObjType::Tree,
                "blob" => ObjType::Blob,
                "tag" => ObjType::Tag,
                other => {
                    l.parse_error = Some(format!("loose object bad type {other}"));
                    l.data = d;
                    return l;
                }
            };
            let body = d[nul + 1..].to_vec();
            l.obj_type = ty;
            l.declared_size = sz;
            if sz as usize != body.len() {
                l.size_deceit = true;
                l.parse_error = Some(format!(
                    "loose size deceit: header {sz}, body {}",
                    body.len()
                ));
            }
            l.oid_by_content = git_object_id(ty.name(), &body);
            l.content_ok = expected_oid
                .map(|e| *e == l.oid_by_content)
                .unwrap_or(true);
            if let Some(e) = expected_oid {
                if *e != l.oid_by_content {
                    l.parse_error = Some(format!(
                        "loose content oid {} does not match filename {}",
                        hex_oid(&l.oid_by_content),
                        hex_oid(e)
                    ));
                }
            }
            l.data = body;
        }
        Err(e) => l.parse_error = Some(e),
    }
    l
}

// ---------- delta application ----------

#[derive(Debug, Clone)]
pub struct DeltaHeader {
    pub base_size: u64,
    pub result_size: u64,
    pub header_len: usize,
}

pub fn read_delta_header(buf: &[u8]) -> Result<DeltaHeader, String> {
    let (base_size, p1) = read_size_varint(buf, 0).ok_or("delta: truncated base size")?;
    let (result_size, p2) = read_size_varint(buf, p1).ok_or("delta: truncated result size")?;
    Ok(DeltaHeader {
        base_size,
        result_size,
        header_len: p2,
    })
}

#[derive(Debug, Clone)]
pub struct DeltaOpRange {
    pub start: usize,
    pub end: usize,
    pub kind: &'static str, // "copy" | "insert"
}

#[derive(Debug, Clone)]
pub struct DeltaApplyOutcome {
    pub result: Vec<u8>,
    pub ops: Vec<DeltaOpRange>,
    pub copy_count: usize,
    pub insert_count: usize,
    pub error: Option<String>,
}

pub fn apply_delta(base: &[u8], delta: &[u8]) -> DeltaApplyOutcome {
    let mut out = DeltaApplyOutcome {
        result: Vec::new(),
        ops: Vec::new(),
        copy_count: 0,
        insert_count: 0,
        error: None,
    };
    let hdr = match read_delta_header(delta) {
        Ok(h) => h,
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    };
    if hdr.base_size as usize != base.len() {
        out.error = Some(format!(
            "delta base-size header {} != actual base length {}",
            hdr.base_size,
            base.len()
        ));
        return out;
    }
    let mut p = hdr.header_len;
    while p < delta.len() {
        let op_start = p;
        let c = delta[p];
        p += 1;
        if c & 0x80 != 0 {
            // COPY from base
            let mut off: u32 = 0;
            let mut len: u32 = 0;
            for i in 0..4 {
                if c & (1 << i) != 0 {
                    if p >= delta.len() {
                        out.error = Some("copy op: truncated offset".to_string());
                        return out;
                    }
                    off |= (delta[p] as u32) << (8 * i);
                    p += 1;
                }
            }
            for i in 0..3 {
                if c & (1 << (4 + i)) != 0 {
                    if p >= delta.len() {
                        out.error = Some("copy op: truncated length".to_string());
                        return out;
                    }
                    len |= (delta[p] as u32) << (8 * i);
                    p += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            let start = off as usize;
            let end = start.checked_add(len as usize);
            match end {
                Some(e) if e <= base.len() => {
                    out.result.extend_from_slice(&base[start..e]);
                }
                _ => {
                    out.error = Some(format!(
                        "copy op OOB: base offset {start} len {len} (base {})",
                        base.len()
                    ));
                    return out;
                }
            }
            out.copy_count += 1;
            out.ops.push(DeltaOpRange {
                start: op_start,
                end: p,
                kind: "copy",
            });
        } else if c != 0 {
            // INSERT literal bytes
            let len = c as usize;
            if p + len > delta.len() {
                out.error = Some("insert op: runs past delta stream".to_string());
                return out;
            }
            out.result.extend_from_slice(&delta[p..p + len]);
            p += len;
            out.insert_count += 1;
            out.ops.push(DeltaOpRange {
                start: op_start,
                end: p,
                kind: "insert",
            });
        } else {
            out.error = Some("opcode 0x00 is reserved".to_string());
            return out;
        }
    }
    if out.result.len() as u64 != hdr.result_size {
        out.error = Some(format!(
            "delta result-size header {} != produced {}",
            hdr.result_size,
            out.result.len()
        ));
    }
    out
}
