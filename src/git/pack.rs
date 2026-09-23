use crate::git::object::ObjType;
use crate::git::zlib::{crc32, inflate_zlib};
use serde::Serialize;

pub const PACK_SIGNATURE: u32 = 0x5041434b; // "PACK"
pub const SUPPORTED_VERSION: u32 = 2;
pub const MAX_INFLATED: usize = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct PackObject {
    /// Offset of the object header within the pack.
    pub offset: u64,
    pub kind: ObjType,
    pub declared_size: usize,
    /// Offset immediately past the zlib stream (next object / trailer).
    pub raw_range_end: u64,
    pub crc32: u32,
    pub zlib_input_consumed: usize,
    pub inflated: Option<Vec<u8>>,
    pub actual_size: Option<usize>,
    /// ofs-delta: absolute offset of the base object.
    pub base_offset: Option<u64>,
    /// ref-delta: 20-byte base object id (hex).
    pub base_ref: Option<String>,
    /// Error evidence (size deceit / zlib failure / ofs underflow).
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PackSummary {
    pub version: u32,
    pub count: u32,
    pub objects: Vec<PackObject>,
    pub trailer_offset: u64,
    pub header_sha_ok: bool,
    pub sha_error: Option<String>,
    pub file_size: u64,
}

fn read_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

fn read_obj_header(buf: &[u8], start: usize) -> Result<(ObjType, usize, usize), String> {
    let first = *buf.get(start).ok_or_else(|| "missing object header".to_string())?;
    let code = (first >> 4) & 0b111;
    let kind = ObjType::from_code(code).ok_or_else(|| format!("unknown type code {}", code))?;
    let mut size = (first & 0x0f) as usize;
    let mut pos = start + 1;
    let mut shift = 4u32;
    let mut cur = first;
    while cur & 0x80 != 0 {
        cur = *buf
            .get(pos)
            .ok_or_else(|| "truncated object header".to_string())?;
        size |= ((cur & 0x7f) as usize) << shift;
        shift += 7;
        pos += 1;
        if shift > 31 {
            return Err("object size header too long".into());
        }
    }
    Ok((kind, size, pos - start))
}

/// Decode ofs-delta relative distance. Returns (absolute base offset, bytes).
fn read_ofs_delta(buf: &[u8], header_end: usize, obj_off: u64) -> Result<(u64, usize), String> {
    let mut pos = header_end;
    let first = *buf
        .get(pos)
        .ok_or_else(|| "missing ofs-delta byte".to_string())?;
    let mut value = (first & 0x7f) as u64;
    pos += 1;
    let mut cur = first;
    while cur & 0x80 != 0 {
        cur = *buf
            .get(pos)
            .ok_or_else(|| "truncated ofs-delta encoding".to_string())?;
        value = value
            .checked_add(1)
            .and_then(|v| v.checked_shl(7))
            .ok_or_else(|| "ofs-delta offset overflow".to_string())?;
        value |= (cur & 0x7f) as u64;
        pos += 1;
    }
    if value > obj_off {
        return Err(format!(
            "ofs-delta distance {} underflows object offset {}",
            value, obj_off
        ));
    }
    Ok((obj_off - value, pos - header_end))
}

fn abort(summary: &mut PackSummary, data: &[u8], msg: String) -> PackSummary {
    let mut s = std::mem::take(summary);
    finalize_trailer(&mut s, data);
    let trailer_err = s.sha_error.take();
    s.sha_error = Some(match trailer_err {
        Some(t) => format!("{}; {}", msg, t),
        None => msg,
    });
    s
}

pub fn parse_pack(data: &[u8]) -> PackSummary {
    let mut summary = PackSummary {
        version: 0,
        count: 0,
        objects: Vec::new(),
        trailer_offset: 0,
        header_sha_ok: false,
        sha_error: None,
        file_size: data.len() as u64,
    };

    if data.len() < 12 {
        return abort(&mut summary, data, "file shorter than 12-byte pack header".into());
    }
    let sig = read_u32(&data[0..4]);
    if sig != PACK_SIGNATURE {
        return abort(&mut summary, data, format!("bad pack signature 0x{:08x}", sig));
    }
    let version = read_u32(&data[4..8]);
    if version != SUPPORTED_VERSION {
        summary.version = version;
        return abort(&mut summary, data, format!("unsupported pack version {}", version));
    }
    let count = read_u32(&data[8..12]);
    summary.version = version;
    summary.count = count;

    let mut cursor = 12usize;
    for _ in 0..count {
        let obj_off = cursor;
        let (kind, declared_size, header_len) = match read_obj_header(data, cursor) {
            Ok(h) => h,
            Err(e) => {
                summary.objects.push(PackObject {
                    offset: obj_off as u64,
                    kind: ObjType::Blob,
                    declared_size: 0,
                    raw_range_end: obj_off as u64,
                    crc32: 0,
                    zlib_input_consumed: 0,
                    inflated: None,
                    actual_size: None,
                    base_offset: None,
                    base_ref: None,
                    error: Some(e),
                });
                return abort(
                    &mut summary,
                    data,
                    format!("stopped at offset {}: bad object header", obj_off),
                );
            }
        };

        let mut base_offset: Option<u64> = None;
        let mut base_ref: Option<String> = None;
        cursor += header_len;

        if kind == ObjType::OfsDelta {
            match read_ofs_delta(data, cursor, obj_off as u64) {
                Ok((abs, consumed)) => {
                    base_offset = Some(abs);
                    cursor += consumed;
                }
                Err(e) => {
                    summary.objects.push(PackObject {
                        offset: obj_off as u64,
                        kind,
                        declared_size,
                        raw_range_end: cursor as u64,
                        crc32: crc32(&data[obj_off..cursor]),
                        zlib_input_consumed: 0,
                        inflated: None,
                        actual_size: None,
                        base_offset: None,
                        base_ref: None,
                        error: Some(e),
                    });
                    return abort(
                        &mut summary,
                        data,
                        format!("stopped at offset {}: ofs distance error", obj_off),
                    );
                }
            }
        } else if kind == ObjType::RefDelta {
            if cursor + 20 > data.len() {
                let e = "ref-delta header overruns pack".to_string();
                summary.objects.push(PackObject {
                    offset: obj_off as u64,
                    kind,
                    declared_size,
                    raw_range_end: cursor as u64,
                    crc32: crc32(&data[obj_off..cursor]),
                    zlib_input_consumed: 0,
                    inflated: None,
                    actual_size: None,
                    base_offset: None,
                    base_ref: None,
                    error: Some(e),
                });
                return abort(
                    &mut summary,
                    data,
                    format!("stopped at offset {}: ref-delta overrun", obj_off),
                );
            }
            base_ref = Some(hex::encode(&data[cursor..cursor + 20]));
            cursor += 20;
        }

        let zlib_start = cursor;
        match inflate_zlib(&data[zlib_start..], MAX_INFLATED) {
            Ok(infl) => {
                let actual = infl.data.len();
                cursor = zlib_start + infl.input_consumed;
                let mut err: Option<String> = None;
                if actual != declared_size {
                    err = Some(format!(
                        "size deceit: header declares {} bytes but zlib produced {}",
                        declared_size, actual
                    ));
                }
                summary.objects.push(PackObject {
                    offset: obj_off as u64,
                    kind,
                    declared_size,
                    raw_range_end: cursor as u64,
                    crc32: crc32(&data[obj_off..cursor]),
                    zlib_input_consumed: infl.input_consumed,
                    inflated: Some(infl.data),
                    actual_size: Some(actual),
                    base_offset,
                    base_ref,
                    error: err,
                });
            }
            Err(e) => {
                summary.objects.push(PackObject {
                    offset: obj_off as u64,
                    kind,
                    declared_size,
                    raw_range_end: zlib_start as u64,
                    crc32: crc32(&data[obj_off..zlib_start]),
                    zlib_input_consumed: 0,
                    inflated: None,
                    actual_size: None,
                    base_offset,
                    base_ref,
                    error: Some(format!("zlib error: {:?}", e)),
                });
                return abort(
                    &mut summary,
                    data,
                    format!("stopped at offset {}: zlib boundary lost", obj_off),
                );
            }
        }
    }

    finalize_trailer(&mut summary, data);
    summary
}

fn finalize_trailer(summary: &mut PackSummary, data: &[u8]) {
    if data.len() < 20 {
        summary.sha_error = Some("missing 20-byte pack checksum trailer".into());
        return;
    }
    summary.trailer_offset = (data.len() - 20) as u64;
    let (body, trailer) = data.split_at(data.len() - 20);
    let calc = crate::git::sha::raw_sha1(body);
    if calc.as_slice() == trailer {
        summary.header_sha_ok = true;
    } else {
        summary.sha_error = Some(format!(
            "pack trailer SHA mismatch: want {} got {}",
            hex::encode(trailer),
            hex::encode(calc)
        ));
    }
}
