// Low level Git object format parsing, implemented from scratch (no `git` binary).

use flate2::Decompress;
use sha1::{Digest, Sha1};

pub fn sha1_hex(bytes: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(bytes);
    let d = h.finalize();
    let mut s = String::with_capacity(40);
    for b in d {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

pub fn parse_oid(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

pub fn oid_hex(b: &[u8; 20]) -> String {
    let mut s = String::with_capacity(40);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xffff_ffff;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

pub fn type_name(t: u8) -> &'static str {
    match t {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        OBJ_OFS_DELTA => "ofs_delta",
        OBJ_REF_DELTA => "ref_delta",
        _ => "unknown",
    }
}

pub fn is_base_type(t: u8) -> bool {
    matches!(t, OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG)
}

pub fn loose_type_from_name(t: &str) -> Option<u8> {
    Some(match t {
        "commit" => OBJ_COMMIT,
        "tree" => OBJ_TREE,
        "blob" => OBJ_BLOB,
        "tag" => OBJ_TAG,
        _ => return None,
    })
}

pub struct InflateGuard {
    pub max_output: usize,
}

pub struct Inflated {
    pub data: Vec<u8>,
    pub consumed: usize,
}

/// Inflate a zlib stream that starts at the beginning of `input`.
/// Returns decompressed bytes and exact count of compressed bytes consumed
/// (the zlib stream boundary).
pub fn inflate_zlib(input: &[u8], guard: &InflateGuard) -> Result<Inflated, String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let chunk = 16 * 1024usize;
    let mut tmp = vec![0u8; chunk];
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let res = d.decompress_vec(input, &mut tmp, flate2::FlushDecompress::None);
        let in_consumed = (d.total_in() - before_in) as usize;
        let out_produced = (d.total_out() - before_out) as usize;
        out.extend_from_slice(&tmp[..out_produced]);
        match res {
            Ok(flate2::Status::Ok) | Ok(flate2::Status::BufError) => {
                if in_consumed == 0 && out_produced == 0 {
                    return Err("zlib stalled".to_string());
                }
                if out.len() > guard.max_output {
                    return Err(format!(
                        "inflated payload exceeds hard guard of {} bytes",
                        guard.max_output
                    ));
                }
            }
            Ok(flate2::Status::StreamEnd) => break,
            Err(e) => return Err(format!("zlib error: {}", e)),
        }
    }
    Ok(Inflated {
        data: out,
        consumed: d.total_in() as usize,
    })
}

#[derive(Debug, Clone)]
pub struct PackHeader {
    pub version: u32,
    pub num_objects: u32,
}

#[derive(Debug, Clone)]
pub enum DeltaRef {
    Ofs { negative_offset: u64 },
    Ref { base_oid: [u8; 20] },
}

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: usize,
    pub header_len: usize,
    pub obj_type: u8,
    pub declared_size: u64,
    pub delta_ref: Option<DeltaRef>,
    pub comp_start: usize,
    pub comp_end: usize,
    pub compressed: Vec<u8>,
    pub crc32: u32,
}

pub struct ParsedPack {
    pub header: PackHeader,
    pub entries: Vec<PackEntry>,
    /// Parse errors keyed by the raw offset where parsing was attempted.
    pub errors: Vec<(usize, String)>,
    pub data_len: usize,
    pub trailer_offset: usize,
    pub checksum_ok: Option<bool>,
}

fn read_size_encoding(buf: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut shift = 0u32;
    let mut size: u64 = 0;
    loop {
        if pos >= buf.len() {
            return Err("truncated size encoding".into());
        }
        let b = buf[pos];
        pos += 1;
        size |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err("size encoding too long".into());
        }
    }
    Ok((size, pos))
}

fn read_ofs_delta(buf: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    if pos >= buf.len() {
        return Err("truncated ofs-delta header".into());
    }
    let mut b = buf[pos];
    pos += 1;
    let mut ofs = (b & 0x7f) as u64;
    while b & 0x80 != 0 {
        if pos >= buf.len() {
            return Err("truncated ofs-delta offset".into());
        }
        b = buf[pos];
        pos += 1;
        ofs = ofs.wrapping_add(1).wrapping_shl(7) | (b & 0x7f) as u64;
    }
    Ok((ofs, pos))
}

pub fn parse_pack(buf: &[u8], guard: &InflateGuard) -> Result<ParsedPack, String> {
    if buf.len() < 12 + 20 {
        return Err("file shorter than pack header + checksum".into());
    }
    if &buf[0..4] != b"PACK" {
        return Err("missing PACK magic".into());
    }
    let version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    let num_objects = u32::from_be_bytes(buf[8..12].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported pack version {}", version));
    }
    let mut entries: Vec<PackEntry> = Vec::new();
    let mut errors: Vec<(usize, String)> = Vec::new();
    let mut pos = 12usize;
    let trailer_offset = buf.len() - 20;
    for _ in 0..num_objects {
        if pos >= trailer_offset {
            errors.push((pos, "ran out of entries before declared count".into()));
            break;
        }
        let entry_offset = pos;
        let first = buf[pos];
        let t = (first >> 4) & 0b111;
        let mut size = (first & 0x0f) as u64;
        pos += 1;
        let mut shift = 4u32;
        while first != 0 && buf[pos - 1] & 0x80 != 0 {
            if pos >= trailer_offset {
                errors.push((entry_offset, "truncated entry header".into()));
                pos = trailer_offset;
                break;
            }
            let b = buf[pos];
            pos += 1;
            size |= ((b & 0x7f) as u64) << shift;
            shift += 7;
        }
        if pos > trailer_offset {
            break;
        }
        let delta_ref = match t {
            OBJ_OFS_DELTA => {
                match read_ofs_delta(buf, pos) {
                    Ok((neg, np)) => {
                        pos = np;
                        Some(DeltaRef::Ofs { negative_offset: neg })
                    }
                    Err(e) => {
                        errors.push((entry_offset, e));
                        break;
                    }
                }
            }
            OBJ_REF_DELTA => {
                if pos + 20 > trailer_offset {
                    errors.push((entry_offset, "truncated ref-delta base name".into()));
                    break;
                }
                let mut base = [0u8; 20];
                base.copy_from_slice(&buf[pos..pos + 20]);
                pos += 20;
                Some(DeltaRef::Ref { base_oid: base })
            }
            _ => None,
        };
        let header_len = pos - entry_offset;
        let comp_start = pos;
        let inflated = match inflate_zlib(&buf[pos..trailer_offset], guard) {
            Ok(v) => v,
            Err(e) => {
                errors.push((entry_offset, format!("cannot inflate object: {}", e)));
                break;
            }
        };
        let comp_end = comp_start + inflated.consumed;
        let crc = crc32_ieee(&buf[entry_offset..comp_end]);
        entries.push(PackEntry {
            offset: entry_offset,
            header_len,
            obj_type: t,
            declared_size: size,
            delta_ref,
            comp_start,
            comp_end,
            compressed: buf[comp_start..comp_end].to_vec(),
            crc32: crc,
        });
        pos = comp_end;
    }
    let checksum_ok = if buf.len() >= 32 {
        Some(sha1_hex(&buf[..trailer_offset]) == oid_hex(buf[trailer_offset..].try_into().unwrap()))
    } else {
        None
    };
    Ok(ParsedPack {
        header: PackHeader { version, num_objects },
        entries,
        errors,
        data_len: buf.len(),
        trailer_offset,
        checksum_ok,
    })
}

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct ParsedIdx {
    pub version: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: [u8; 20],
    pub idx_checksum: [u8; 20],
    pub idx_checksum_ok: bool,
}

pub fn parse_idx(buf: &[u8]) -> Result<ParsedIdx, String> {
    let v2_magic = [0xffu8, 0x74, 0x4f, 0x63];
    let mut fanout = [0u32; 256];
    let (version, mut pos) = if buf.len() >= 8 && buf[0..4] == v2_magic {
        let v = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        if v != 2 {
            return Err(format!("unsupported idx version {}", v));
        }
        (2u32, 8usize)
    } else {
        (1u32, 0usize)
    };
    if buf.len() < pos + 256 * 4 {
        return Err("idx too short for fanout table".into());
    }
    for i in 0..256 {
        fanout[i] = u32::from_be_bytes(buf[pos + i * 4..pos + i * 4 + 4].try_into().unwrap());
    }
    pos += 256 * 4;
    let n = fanout[255] as usize;
    if n > 50_000_000 {
        return Err("idx fanout object count implausible".into());
    }
    let mut names: Vec<[u8; 20]> = Vec::with_capacity(n);
    if version == 2 {
        if buf.len() < pos + n * 20 {
            return Err("idx truncated in sha1 table".into());
        }
        for i in 0..n {
            let mut o = [0u8; 20];
            o.copy_from_slice(&buf[pos + i * 20..pos + i * 20 + 20]);
            names.push(o);
        }
        pos += n * 20;
        let mut crcs = vec![0u32; n];
        if buf.len() < pos + n * 4 {
            return Err("idx truncated in crc table".into());
        }
        for i in 0..n {
            crcs[i] = u32::from_be_bytes(buf[pos + i * 4..pos + i * 4 + 4].try_into().unwrap());
        }
        pos += n * 4;
        let off_table_pos = pos;
        let mut raw_offsets = vec![0u32; n];
        if buf.len() < pos + n * 4 {
            return Err("idx truncated in offset table".into());
        }
        for i in 0..n {
            raw_offsets[i] =
                u32::from_be_bytes(buf[pos + i * 4..pos + i * 4 + 4].try_into().unwrap());
        }
        pos += n * 4;
        let large_count = raw_offsets
            .iter()
            .filter(|o| *o & 0x8000_0000 != 0)
            .count();
        if buf.len() < pos + large_count * 8 + 40 {
            return Err("idx large-offset table truncated".into());
        }
        let mut entries = Vec::with_capacity(n);
        for i in 0..n {
            let raw = raw_offsets[i];
            let off = if raw & 0x8000_0000 != 0 {
                let idx = (raw & 0x7fff_ffff) as usize;
                let p = off_table_pos + n * 4 + idx * 8;
                u64::from_be_bytes(buf[p..p + 8].try_into().unwrap())
            } else {
                raw as u64
            };
            entries.push(IdxEntry {
                oid: names[i],
                crc32: crcs[i],
                offset: off,
            });
        }
        pos += large_count * 8;
        if buf.len() < pos + 40 {
            return Err("idx missing trailing checksums".into());
        }
        let mut pack_checksum = [0u8; 20];
        pack_checksum.copy_from_slice(&buf[buf.len() - 40..buf.len() - 20]);
        let mut idx_checksum = [0u8; 20];
        idx_checksum.copy_from_slice(&buf[buf.len() - 20..]);
        let computed = sha1_hex(&buf[..buf.len() - 20]);
        return Ok(ParsedIdx {
            version,
            fanout,
            entries,
            pack_checksum,
            idx_checksum,
            idx_checksum_ok: computed == oid_hex(&idx_checksum),
        });
    }
    // v1: 256 fanout + n * (4 offset + 20 sha1)
    if buf.len() < pos + n * 24 + 40 {
        return Err("idx v1 truncated".into());
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let off = u32::from_be_bytes(buf[pos + i * 24..pos + i * 24 + 4].try_into().unwrap()) as u64;
        let mut o = [0u8; 20];
        o.copy_from_slice(&buf[pos + i * 24 + 4..pos + i * 24 + 24]);
        entries.push(IdxEntry { oid: o, crc32: 0, offset: off });
    }
    pos += n * 24;
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&buf[pos..pos + 20]);
    let mut idx_checksum = [0u8; 20];
    idx_checksum.copy_from_slice(&buf[pos + 20..pos + 40]);
    let computed = sha1_hex(&buf[..pos + 20]);
    Ok(ParsedIdx {
        version,
        fanout,
        entries,
        pack_checksum,
        idx_checksum,
        idx_checksum_ok: computed == oid_hex(&idx_checksum),
    })
}

pub struct ParsedLoose {
    pub obj_type: u8,
    pub size: u64,
    pub content: Vec<u8>,
}

/// Parse an inflated loose object stream: `<type> <size>\0<content>`.
pub fn parse_loose_content(raw: &[u8]) -> Result<ParsedLoose, String> {
    let nul = raw
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| "loose object missing NUL separator".to_string())?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| "loose header not utf-8")?;
    let (name, size_s) = header
        .split_once(' ')
        .ok_or_else(|| "loose header malformed".to_string())?;
    let obj_type = loose_type_from_name(name)
        .ok_or_else(|| format!("unknown loose object type `{}`", name))?;
    let size: u64 = size_s
        .parse()
        .map_err(|_| "loose header size not a number".to_string())?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != size {
        return Err(format!(
            "loose size spoof: header declares {} but content is {} bytes",
            size,
            content.len()
        ));
    }
    Ok(ParsedLoose { obj_type, size, content })
}

pub fn parse_loose_file(buf: &[u8], guard: &InflateGuard) -> Result<ParsedLoose, String> {
    let inflated = inflate_zlib(buf, guard)?;
    parse_loose_content(&inflated.data)
}

/// Build the canonical on-disk representation used for the Git object id:
/// `<type> <len>\0<content>`.
pub fn git_object_frame(obj_type: u8, content: &[u8]) -> Vec<u8> {
    let header = format!("{} {}\0", type_name(obj_type), content.len());
    let mut out = Vec::with_capacity(header.len() + content.len());
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(content);
    out
}

pub fn git_object_id(obj_type: u8, content: &[u8]) -> String {
    sha1_hex(&git_object_frame(obj_type, content))
}

pub struct DeltaInstruction {
    pub kind: &'static str,
    /// Byte range inside the delta instruction stream.
    pub range_start: usize,
    pub range_end: usize,
    pub copy_offset: u64,
    pub copy_size: u64,
    pub insert_len: u64,
}

pub struct AppliedDelta {
    pub base_size: u64,
    pub result_size: u64,
    pub result: Vec<u8>,
    pub instructions: Vec<DeltaInstruction>,
}

/// Apply a Git delta (the inflated payload of an ofs/ref-delta object) to a
/// fully resolved base object. Instruction byte ranges are recorded for the
/// forensic step log.
pub fn apply_delta(base: &[u8], delta: &[u8], max_result: usize) -> Result<AppliedDelta, String> {
    let mut p = 0usize;
    let read_var = |p: &mut usize| -> Result<u64, String> {
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            if *p >= delta.len() {
                return Err("delta size encoding truncated".into());
            }
            let b = delta[*p];
            *p += 1;
            v |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 63 {
                return Err("delta size encoding too long".into());
            }
        }
        Ok(v)
    };
    let base_size = read_var(&mut p)?;
    let result_size = read_var(&mut p)?;
    if base_size as usize != base.len() {
        return Err(format!(
            "delta base size mismatch: delta expects {}, actual base is {}",
            base_size,
            base.len()
        ));
    }
    if result_size as usize > max_result {
        return Err(format!(
            "delta result size {} exceeds per-object budget {}",
            result_size, max_result
        ));
    }
    let mut result = Vec::with_capacity(result_size.min(max_result as u64) as usize);
    let mut instructions = Vec::new();
    while p < delta.len() {
        let op = delta[p];
        let start = p;
        p += 1;
        if op & 0x80 != 0 {
            let mut off: u64 = 0;
            let mut size: u64 = 0;
            for i in 0..4 {
                if op & (1 << i) != 0 {
                    if p >= delta.len() {
                        return Err("copy opcode missing offset byte".into());
                    }
                    off |= (delta[p] as u64) << (8 * i);
                    p += 1;
                }
            }
            for i in 0..3 {
                if op & (1 << (4 + i)) != 0 {
                    if p >= delta.len() {
                        return Err("copy opcode missing size byte".into());
                    }
                    size |= (delta[p] as u64) << (8 * i);
                    p += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = off.checked_add(size).ok_or("copy range overflow")? as usize;
            if end > base.len() {
                return Err(format!(
                    "copy reads outside base: offset={} size={} base_len={}",
                    off, size, base.len()
                ));
            }
            result.extend_from_slice(&base[off as usize..end]);
            instructions.push(DeltaInstruction {
                kind: "copy",
                range_start: start,
                range_end: p,
                copy_offset: off,
                copy_size: size,
                insert_len: 0,
            });
        } else if op != 0 {
            let len = op as usize;
            if p + len > delta.len() {
                return Err("insert opcode runs past delta end".into());
            }
            result.extend_from_slice(&delta[p..p + len]);
            p += len;
            instructions.push(DeltaInstruction {
                kind: "insert",
                range_start: start,
                range_end: p,
                copy_offset: 0,
                copy_size: 0,
                insert_len: len as u64,
            });
        } else {
            return Err("delta opcode 0x00 is reserved".into());
        }
        if result.len() > result_size as usize {
            return Err("delta output exceeds declared result size".into());
        }
    }
    if result.len() as u64 != result_size {
        return Err(format!(
            "delta result size spoof: header declares {} but produced {}",
            result_size,
            result.len()
        ));
    }
    Ok(AppliedDelta {
        base_size,
        result_size,
        result,
        instructions,
    })
}
