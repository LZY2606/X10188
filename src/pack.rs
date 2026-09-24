use crate::hash;
use crate::model::{BaseRef, ObjType};
use crate::zlibx;

/// Per-object hard cap on decompressed payload (zip-bomb guard at import time).
pub const IMPORT_DECOMPRESS_CAP: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct PackObject {
    pub offset: u64,
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub data_offset: u64,
    /// length of the zlib compressed region
    pub compressed_len: u64,
    /// total on-disk length from object header to end of zlib stream
    pub raw_len: u64,
    pub base: Option<BaseRef>,
    /// decompressed zlib payload (object content, or delta instruction stream)
    pub payload: Option<Vec<u8>>,
    /// crc32 of the raw on-disk representation (header + compressed data)
    pub crc32: u32,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub objects: Vec<PackObject>,
    pub trailer_ok: bool,
    pub fatal: Option<String>,
    /// declared object count minus successfully located objects
    pub unlocated: usize,
    pub trailer_offset: Option<u64>,
}

fn read_u32(b: &[u8], p: usize) -> u32 {
    u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}

/// Parse one object header starting at `pos`.
/// Returns (type, declared size, next position).
fn read_obj_header(b: &[u8], pos: usize) -> Result<(ObjType, u64, usize), String> {
    let first = *b.get(pos).ok_or("对象头部越界".to_string())?;
    let code = (first >> 4) & 0x07;
    let typ = ObjType::from_code(code).ok_or_else(|| format!("未知对象类型 code={code}"))?;
    let mut size = u64::from(first & 0x0f);
    let mut shift = 4u32;
    let mut p = pos + 1;
    if first & 0x80 != 0 {
        loop {
            let c = *b.get(p).ok_or("对象大小可变长度整数越界".to_string())?;
            p += 1;
            size |= u64::from(c & 0x7f) << shift;
            shift += 7;
            if c & 0x80 == 0 {
                break;
            }
        }
    }
    Ok((typ, size, p))
}

/// Parse an ofs-delta negative-distance field, returning (absolute base offset, next pos).
fn read_ofs_distance(b: &[u8], pos: usize, obj_offset: u64) -> Result<(u64, usize), String> {
    let mut p = pos;
    let mut c = *b.get(p).ok_or("ofs-delta 距离字节缺失")?;
    p += 1;
    let mut dist = u64::from(c & 0x7f);
    while c & 0x80 != 0 {
        c = *b.get(p).ok_or("ofs-delta 距离变长整数越界")?;
        p += 1;
        dist = ((dist + 1) << 7) | u64::from(c & 0x7f);
    }
    obj_offset
        .checked_sub(dist)
        .map(|base| (base, p))
        .ok_or_else(|| format!("ofs 距离越界: offset={obj_offset} distance={dist}"))
}

/// Parse a whole pack file.
///
/// `resync_offsets` (e.g. offsets learned from an index) lets the parser recover
/// the stream position after a corrupt zlib object, so later objects can still
/// be isolated and analysed.
pub fn parse_pack(bytes: &[u8], resync_offsets: &[u64]) -> ParsedPack {
    let mut result = ParsedPack {
        version: 0,
        count: 0,
        objects: Vec::new(),
        trailer_ok: false,
        fatal: None,
        unlocated: 0,
        trailer_offset: None,
    };

    if bytes.len() < 32 {
        result.fatal = Some("文件长度不足 pack 最小长度（32 字节）".to_string());
        return result;
    }
    if &bytes[0..4] != b"PACK" {
        result.fatal = Some("缺少 PACK 魔数".to_string());
        return result;
    }
    result.version = read_u32(bytes, 4);
    result.count = read_u32(bytes, 8);
    if result.version != 2 && result.version != 3 {
        result.fatal = Some(format!("不支持的 pack 版本 {}", result.version));
        return result;
    }

    let trailer_at = bytes.len() - 20;
    result.trailer_offset = Some(trailer_at as u64);
    let want = hash::sha1_bytes(&bytes[..trailer_at]);
    result.trailer_ok = want.as_slice() == &bytes[trailer_at..];

    let mut pos = 12usize;
    for index in 0..result.count {
        if pos >= trailer_at {
            result.unlocated = (result.count - index) as usize;
            result.fatal = Some(format!("对象流在第 {index} 个对象处触及 trailer，剩余对象缺失"));
            break;
        }
        let offset = pos as u64;
        match parse_one_object(bytes, &mut pos, trailer_at, offset, resync_offsets) {
            Some(o) => result.objects.push(o),
            None => {
                result.unlocated = (result.count - index) as usize;
                result.fatal = Some(format!(
                    "对象流在 offset={offset} 处无法继续定位，剩余 {} 个对象未能解析",
                    result.count - index
                ));
                break;
            }
        }
    }
    result
}

/// Find the next resync offset strictly greater than `from`.
fn resync_after(from: usize, trailer_at: usize, resync_offsets: &[u64]) -> usize {
    let from = from as u64;
    let mut best: Option<u64> = None;
    for o in resync_offsets {
        if *o > from && (*o as usize) < trailer_at {
            best = Some(match best {
                Some(b) if b < *o => b,
                _ => *o,
            });
        }
    }
    best.map(|b| b as usize).unwrap_or(trailer_at)
}

fn broken_object(offset: u64, obj_type: ObjType, declared_size: u64, data_offset: u64, base: Option<BaseRef>, err: String) -> PackObject {
    PackObject {
        offset,
        obj_type,
        declared_size,
        data_offset,
        compressed_len: 0,
        raw_len: 0,
        base,
        payload: None,
        crc32: 0,
        error: Some(err),
    }
}

fn parse_one_object(
    bytes: &[u8],
    pos: &mut usize,
    trailer_at: usize,
    offset: u64,
    resync_offsets: &[u64],
) -> Option<PackObject> {
    let start = *pos;
    let (obj_type, declared_size, after_header) = match read_obj_header(bytes, start) {
        Ok(v) => v,
        Err(e) => {
            *pos = resync_after(start, trailer_at, resync_offsets);
            return Some(broken_object(offset, ObjType::Blob, 0, start as u64, None, e));
        }
    };
    *pos = after_header;

    let mut base = None;
    match obj_type {
        ObjType::OfsDelta => match read_ofs_distance(bytes, *pos, offset) {
            Ok((base_ofs, next)) => {
                base = Some(BaseRef::Ofs(base_ofs));
                *pos = next;
            }
            Err(e) => {
                *pos = resync_after(*pos, trailer_at, resync_offsets);
                return Some(broken_object(offset, obj_type, declared_size, *pos as u64, None, e));
            }
        },
        ObjType::RefDelta => {
            if *pos + 20 > trailer_at {
                *pos = resync_after(*pos, trailer_at, resync_offsets);
                return Some(broken_object(
                    offset,
                    obj_type,
                    declared_size,
                    *pos as u64,
                    None,
                    "ref-delta 的 20 字节 base oid 越界".to_string(),
                ));
            }
            let oid = hash::hex(&bytes[*pos..*pos + 20]);
            base = Some(BaseRef::Ref(oid));
            *pos += 20;
        }
        _ => {}
    }
    let data_offset = *pos as u64;

    match zlibx::decompress_with_boundary(&bytes[*pos..trailer_at], IMPORT_DECOMPRESS_CAP) {
        Ok((payload, consumed)) => {
            let end = *pos + consumed;
            let raw_len = (end - start) as u64;
            let crc = hash::crc32(&bytes[start..end]);
            *pos = end;
            Some(PackObject {
                offset,
                obj_type,
                declared_size,
                data_offset,
                compressed_len: consumed as u64,
                raw_len,
                base,
                payload: Some(payload),
                crc32: crc,
                error: None,
            })
        }
        Err(e) => {
            // The zlib boundary is unknown; resync to the next known offset if any.
            let next = resync_after(*pos, trailer_at, resync_offsets);
            let raw_len = if next > start { (next - start) as u64 } else { 0 };
            *pos = next;
            let mut obj = broken_object(offset, obj_type, declared_size, data_offset, base, e);
            obj.raw_len = raw_len;
            Some(obj)
        }
    }
}

// ---- encoders (shared with tests) ------------------------------------------

pub enum BaseSpec {
    /// base is another object in the same pack, addressed by index
    Obj(usize),
    /// base referenced by object id
    Ref(String),
}

pub mod encode {
    use super::{hash, zlibx, BaseRef, BaseSpec, ObjType};

    pub fn obj_header(typ: ObjType, size: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut first = (typ.code() << 4) | ((size as u8) & 0x0f);
        let mut rest = size >> 4;
        if rest != 0 {
            first |= 0x80;
        }
        out.push(first);
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

    pub fn ofs_distance(mut dist: u64) -> Vec<u8> {
        let mut bytes = vec![(dist & 0x7f) as u8];
        while dist >> 7 != 0 {
            dist = (dist >> 7) - 1;
            bytes.push(((dist & 0x7f) as u8) | 0x80);
        }
        bytes.reverse();
        bytes
    }

    /// Build one on-disk object (header [base reference] zlib(payload)).
    /// `BaseRef::Ofs` carries the *distance* here.
    pub fn object(typ: ObjType, payload: &[u8], base: Option<&BaseRef>) -> Vec<u8> {
        let mut out = obj_header(typ, payload.len() as u64);
        match base {
            Some(BaseRef::Ofs(dist)) => out.extend_from_slice(&ofs_distance(*dist)),
            Some(BaseRef::Ref(oid)) => out.extend_from_slice(&hash::unhex(oid).unwrap()),
            None => {}
        }
        out.extend_from_slice(&zlibx::compress(payload));
        out
    }

    /// Assemble a pack, fixing up ofs-delta distances. Iterates the layout to a
    /// fixed point because distance varints can change length.
    pub fn pack(objects: &[(ObjType, Vec<u8>, Option<BaseSpec>)]) -> Vec<u8> {
        let mut offsets = vec![12usize; objects.len()];
        for _ in 0..8 {
            let mut p = 12usize;
            let mut next_offsets = Vec::with_capacity(objects.len());
            for (i, (typ, payload, base)) in objects.iter().enumerate() {
                next_offsets.push(p);
                let base_ref = match base {
                    Some(BaseSpec::Obj(j)) => Some(BaseRef::Ofs((offsets[i] - offsets[*j]) as u64)),
                    Some(BaseSpec::Ref(o)) => Some(BaseRef::Ref(o.clone())),
                    None => None,
                };
                p += object(*typ, payload, base_ref.as_ref()).len();
            }
            if next_offsets == offsets {
                break;
            }
            offsets = next_offsets;
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&(objects.len() as u32).to_be_bytes());
        for (i, (typ, payload, base)) in objects.iter().enumerate() {
            let base_ref = match base {
                Some(BaseSpec::Obj(j)) => Some(BaseRef::Ofs((offsets[i] - offsets[*j]) as u64)),
                Some(BaseSpec::Ref(o)) => Some(BaseRef::Ref(o.clone())),
                None => None,
            };
            out.extend_from_slice(&object(*typ, payload, base_ref.as_ref()));
        }
        out.extend_from_slice(&hash::sha1_bytes(&out));
        out
    }
}
