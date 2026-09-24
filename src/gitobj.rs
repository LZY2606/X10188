use crate::types::FailReason;
use sha1::{Digest, Sha1};

/// Compute a Git loose-object id for the given payload.
pub fn git_object_id(kind: crate::types::ObjType, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(kind.loose_name().unwrap_or("blob").as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    let out = h.finalize();
    let mut id = [0u8; 20];
    id.copy_from_slice(&out);
    id
}

pub fn oid_hex(id: &[u8; 20]) -> String {
    hex::encode(id)
}

/// LEB128 style little-endian base-128 used by pack entry headers and delta headers.
pub fn read_size_varint(data: &[u8], pos: &mut usize) -> Result<u64, String> {
    let mut shift = 0u32;
    let mut result = 0u64;
    loop {
        if *pos >= data.len() {
            return Err("varint 被截断".into());
        }
        let b = data[*pos];
        *pos += 1;
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err("varint 过长".into());
        }
    }
    Ok(result)
}

/// Pack entry header: (type, uncompressed size, header_len).
pub fn read_pack_entry_header(data: &[u8], start: usize) -> Result<(crate::types::ObjType, u64, usize), String> {
    if start + 1 > data.len() {
        return Err("pack entry 起始位置越界".into());
    }
    let first = data[start];
    let code = (first >> 4) & 0x07;
    let kind = crate::types::ObjType::from_pack_code(code)
        .ok_or_else(|| format!("未知对象类型代码 {code}"))?;
    let mut size = u64::from(first & 0x0f);
    let mut pos = start + 1;
    let mut shift = 4u32;
    if first & 0x80 != 0 {
        loop {
            if pos >= data.len() {
                return Err("pack entry header 被截断".into());
            }
            let b = data[pos];
            pos += 1;
            size |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err("pack entry header 过长".into());
            }
        }
    }
    Ok((kind, size, pos - start))
}

/// Encode a pack entry header (size in the varint payload).
pub fn write_pack_entry_header(kind: crate::types::ObjType, size: u64) -> Vec<u8> {
    let code = match kind {
        crate::types::ObjType::Commit => 1u8,
        crate::types::ObjType::Tree => 2,
        crate::types::ObjType::Blob => 3,
        crate::types::ObjType::Tag => 4,
        crate::types::ObjType::OfsDelta => 6,
        crate::types::ObjType::RefDelta => 7,
    };
    let mut out = Vec::new();
    let mut first = (code << 4) | ((size as u8) & 0x0f);
    let mut rest = size >> 4;
    if rest != 0 {
        first |= 0x80;
    }
    out.push(first);
    while rest != 0 {
        let mut b = (rest as u8) & 0x7f;
        rest >>= 7;
        if rest != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
    out
}

/// Decode an ofs-delta negative offset encoded with the pack convention.
/// Returns (offset_value, bytes_consumed).
pub fn read_ofs_delta(data: &[u8], pos: &mut usize) -> Result<(u64, usize), String> {
    if *pos >= data.len() {
        return Err("ofs-delta 被截断".into());
    }
    let start = *pos;
    let mut b = data[*pos];
    *pos += 1;
    let mut ofs = u64::from(b & 0x7f);
    while b & 0x80 != 0 {
        if *pos >= data.len() {
            return Err("ofs-delta 多字节被截断".into());
        }
        b = data[*pos];
        *pos += 1;
        ofs = ofs.wrapping_add(1).wrapping_shl(7) | u64::from(b & 0x7f);
    }
    Ok((ofs, *pos - start))
}

/// Encode an ofs-delta negative offset (used by the in-repo test pack builder).
pub fn write_ofs_delta(value: u64) -> Vec<u8> {
    assert!(value >= 1, "ofs delta must be positive");
    let mut bytes = vec![(value & 0x7f) as u8];
    let mut v = value >> 7;
    while v != 0 {
        v -= 1;
        bytes.push(0x80 | ((v & 0x7f) as u8));
        v >>= 7;
    }
    bytes.reverse();
    bytes
}

/// Plain LEB128 writer for delta header sizes.
pub fn write_size_leb128(mut size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut b = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            b |= 0x80;
        }
        out.push(b);
        if size == 0 {
            break;
        }
    }
    out
}

/// Result of a single zlib stream inflation with exact byte boundaries.
pub struct Inflated {
    pub data: Vec<u8>,
    /// Offset (relative to the input slice start) where the stream ends.
    pub consumed: usize,
    /// Raw bytes of the compressed zlib stream.
    pub stream: Vec<u8>,
}

/// Inflate exactly one zlib stream starting at `data[start]`.
///
/// * `declared_size` — the size promised by the pack entry header. Detection
///   of a "size spoof" happens here: a stream that inflates to a different
///   length is reported. Truncation mid-stream is detected too.
pub fn inflate_one(data: &[u8], start: usize, declared_size: u64) -> Result<Inflated, FailReason> {
    use flate2::Decompress;
    let mut d = Decompress::new(true);
    let cap = if declared_size > 0 {
        declared_size as usize
    } else {
        1024
    };
    let mut out: Vec<u8> = Vec::with_capacity(cap.min(1 << 20));
    let mut in_pos = start;
    let mut chunk_in = 0usize;
    let mut last_status = flate2::Status::Ok;
    let cap_limit: usize = (declared_size as usize)
        .checked_add(64 * 1024)
        .unwrap_or(usize::MAX);
    loop {
        if in_pos >= data.len() {
            return Err(FailReason::InflateError("压缩流在结束前截断".into()));
        }
        let avail_in = (data.len() - in_pos).min(64 * 1024);
        let before_out = out.len();
        out.resize(before_out + 64 * 1024, 0);
        let before_in = d.total_in();
        let result = d.decompress(
            &data[in_pos..in_pos + avail_in],
            &mut out[before_out..],
            flate2::FlushDecompress::None,
        );
        let in_used = (d.total_in() - before_in) as usize;
        in_pos += in_used;
        chunk_in += in_used;
        match result {
            Ok(status) => {
                let written = (d.total_out() as usize) - before_out;
                out.truncate(before_out + written);
                last_status = status;
                if status == flate2::Status::StreamEnd {
                    break;
                }
                if status == flate2::Status::Ok && in_used == 0 && written == 0 {
                    return Err(FailReason::InflateError("解压停滞且流未结束".into()));
                }
                if out.len() > cap_limit {
                    return Err(FailReason::SizeSpoof {
                        declared: declared_size,
                        actual: out.len() as u64,
                    });
                }
            }
            Err(e) => {
                out.truncate(before_out);
                return Err(FailReason::InflateError(e.to_string()));
            }
        }
    }
    if out.len() as u64 != declared_size {
        return Err(FailReason::SizeSpoof {
            declared: declared_size,
            actual: out.len() as u64,
        });
    }
    let consumed = (d.total_in() as usize) + start;
    let _ = last_status;
    let _ = chunk_in;
    Ok(Inflated {
        data: out,
        consumed,
        stream: data[start..consumed.min(data.len())].to_vec(),
    })
}

pub fn deflate(data: &[u8]) -> Vec<u8> {
    use flate2::write::ZlibEncoder;
    use std::io::Write;
    let mut e = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

// ---------- CRC32 (IEEE 802.3, same as zlib.crc32 / Git) ----------

fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0usize;
    while n < 256 {
        let mut c = n as u32;
        let mut k = 0;
        while k < 8 {
            if c & 1 != 0 {
                c = 0xedb8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            k += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

pub fn crc32(data: &[u8]) -> u32 {
    let table = crc_table();
    let mut c: u32 = 0xffff_ffff;
    for &b in data {
        c = table[((c ^ u32::from(b)) & 0xff) as usize] ^ (c >> 8);
    }
    c ^ 0xffff_ffff
}

/// Short preview used in the UI: text or hex dump.
pub fn preview(bytes: &[u8], max: usize) -> (String, bool) {
    let slice = &bytes[..bytes.len().min(max)];
    let is_text = !slice
        .iter()
        .any(|&b| b == 0 || (b < 0x09 && b != 0x09) || b == 0x7f);
    if is_text {
        (String::from_utf8_lossy(slice).to_string(), true)
    } else {
        let mut s = String::new();
        for (i, b) in slice.iter().enumerate() {
            if i % 16 == 0 && i != 0 {
                s.push('\n');
            }
            s.push_str(&format!("{b:02x} "));
        }
        (s, false)
    }
}
