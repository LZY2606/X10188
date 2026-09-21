//! Pure-Rust Git pack parser: header, entry varints, ofs/ref delta bases,
//! zlib stream boundary detection and declared-size verification.
use flate2::{Decompress, FlushDecompress, Status};

/// Hard cap on a single inflated object, guards against absurd declared sizes.
pub const HARD_CAP: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RawEntry {
    pub offset: u64,
    pub otype: u8,
    pub declared_size: u64,
    pub data_offset: u64,
    pub comp_len: u64,
    pub base_offset: Option<u64>,
    pub base_oid: Option<String>,
    pub inflated: Option<Vec<u8>>,
    pub error: Option<String>,
    pub crc32: u32,
}

#[derive(Debug)]
pub struct PackParse {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<RawEntry>,
    pub trailer: String,
    pub trailer_ok: bool,
    pub errors: Vec<String>,
}

/// Inflate a zlib stream starting at `input[0]`, enforcing the declared size.
/// Returns (inflated, compressed_len). Detects size deception mid-stream:
/// as soon as output exceeds the declared size we fail instead of trusting it.
pub fn inflate_bounded(input: &[u8], expected: u64) -> Result<(Vec<u8>, usize), String> {
    if expected + 1 > HARD_CAP {
        return Err(format!("declared size {} exceeds hard cap", expected));
    }
    let mut d = Decompress::new(true);
    let mut out = vec![0u8; (expected + 1) as usize];
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let status = d
            .decompress(input, &mut out, FlushDecompress::None)
            .map_err(|e| format!("zlib corrupt: {}", e))?;
        if d.total_out() > expected {
            return Err(format!(
                "size deception: stream produced more than declared {} bytes",
                expected
            ));
        }
        match status {
            Status::StreamEnd => break,
            _ => {
                if d.total_in() == before_in && d.total_out() == before_out {
                    return Err(format!(
                        "truncated zlib stream at {} bytes (declared {})",
                        d.total_out(),
                        expected
                    ));
                }
            }
        }
    }
    let mut v = out;
    v.truncate(d.total_out() as usize);
    Ok((v, d.total_in() as usize))
}

/// Inflate a zlib stream of unknown size (loose objects), capped.
pub fn inflate_unknown(input: &[u8], cap: u64) -> Result<(Vec<u8>, usize), String> {
    let mut d = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let before_in = d.total_in();
        let before_out = d.total_out();
        let status = d
            .decompress(input, &mut chunk, FlushDecompress::None)
            .map_err(|e| format!("zlib corrupt: {}", e))?;
        let produced = (d.total_out() - before_out) as usize;
        out.extend_from_slice(&chunk[..produced]);
        if out.len() as u64 > cap {
            return Err(format!("inflated data exceeds cap of {} bytes", cap));
        }
        match status {
            Status::StreamEnd => break,
            _ => {
                if d.total_in() == before_in && produced == 0 {
                    return Err("truncated zlib stream".into());
                }
            }
        }
    }
    Ok((out, d.total_in() as usize))
}

fn parse_entry_header(data: &[u8], pos: usize) -> Result<(u8, u64, usize), String> {
    let mut p = pos;
    let c = *data.get(p).ok_or("truncated entry header")?;
    p += 1;
    let otype = (c >> 4) & 0x7;
    let mut size = (c & 0x0f) as u64;
    let mut shift = 4u32;
    let mut b = c;
    while b & 0x80 != 0 {
        b = *data.get(p).ok_or("truncated entry header")?;
        p += 1;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        if shift > 63 {
            return Err("entry size varint overflow".into());
        }
    }
    Ok((otype, size, p))
}

fn parse_ofs_base(data: &[u8], pos: usize) -> Result<(u64, usize), String> {
    let mut p = pos;
    let mut c = *data.get(p).ok_or("truncated ofs-delta base")?;
    p += 1;
    let mut dist = (c & 0x7f) as u64;
    while c & 0x80 != 0 {
        c = *data.get(p).ok_or("truncated ofs-delta base")?;
        p += 1;
        dist = ((dist + 1) << 7) | ((c & 0x7f) as u64);
    }
    Ok((dist, p))
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

pub fn parse_pack(data: &[u8]) -> PackParse {
    let mut errors = Vec::new();
    let mut entries = Vec::new();
    let mut version = 0u32;
    let mut count = 0u32;
    let mut trailer = String::new();
    let mut trailer_ok = false;

    if data.len() < 12 + 20 || &data[0..4] != b"PACK" {
        errors.push("bad pack magic or too short".into());
        return PackParse { version, count, entries, trailer, trailer_ok, errors };
    }
    version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 && version != 3 {
        errors.push(format!("unsupported pack version {}", version));
    }
    count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    let body_end = data.len() - 20;
    trailer = hex::encode(&data[body_end..]);
    trailer_ok = crate::gitobj::sha1_hex(&data[..body_end]) == trailer;
    if !trailer_ok {
        errors.push("pack trailer checksum mismatch".into());
    }

    let mut pos = 12usize;
    for idx in 0..count {
        let entry_offset = pos as u64;
        let (otype, declared, p1) = match parse_entry_header(data, pos) {
            Ok(v) => v,
            Err(e) => {
                errors.push(format!("entry #{} @{}: {}", idx, entry_offset, e));
                break;
            }
        };
        pos = p1;
        let mut base_offset = None;
        let mut base_oid = None;
        let mut entry_error: Option<String> = None;
        match otype {
            6 => match parse_ofs_base(data, pos) {
                Ok((dist, p2)) => {
                    pos = p2;
                    if dist == 0 || dist >= entry_offset.saturating_sub(11) {
                        entry_error = Some(format!(
                            "ofs distance {} out of bounds at offset {}",
                            dist, entry_offset
                        ));
                    } else {
                        base_offset = Some(entry_offset - dist);
                    }
                }
                Err(e) => {
                    errors.push(format!("entry #{} @{}: {}", idx, entry_offset, e));
                    break;
                }
            },
            7 => {
                if pos + 20 > body_end {
                    errors.push(format!("entry #{} @{}: truncated ref-delta base", idx, entry_offset));
                    break;
                }
                base_oid = Some(hex::encode(&data[pos..pos + 20]));
                pos += 20;
            }
            1..=4 => {}
            _ => {
                entry_error = Some(format!("unknown object type code {}", otype));
            }
        }
        let data_offset = pos as u64;
        let mut inflated = None;
        let mut comp_len = 0u64;
        match inflate_bounded(&data[pos..body_end], declared) {
            Ok((out, used)) => {
                comp_len = used as u64;
                inflated = Some(out);
            }
            Err(e) => {
                entry_error = Some(match entry_error.take() {
                    Some(prev) => format!("{}; {}", prev, e),
                    None => e,
                });
                entries.push(RawEntry {
                    offset: entry_offset,
                    otype,
                    declared_size: declared,
                    data_offset,
                    comp_len: 0,
                    base_offset,
                    base_oid,
                    inflated: None,
                    error: entry_error.clone(),
                    crc32: 0,
                });
                errors.push(format!("entry #{} @{}: {}", idx, entry_offset, e));
                break;
            }
        }
        let end = (data_offset + comp_len) as usize;
        let crc = crc32(&data[entry_offset as usize..end]);
        entries.push(RawEntry {
            offset: entry_offset,
            otype,
            declared_size: declared,
            data_offset,
            comp_len,
            base_offset,
            base_oid,
            inflated,
            error: entry_error,
            crc32: crc,
        });
        pos = end;
    }
    if entries.len() < count as usize {
        errors.push(format!(
            "pack ended after {} of {} declared entries",
            entries.len(),
            count
        ));
    }
    PackParse { version, count, entries, trailer, trailer_ok, errors }
}
