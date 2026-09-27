//! pack 文件解析：header、对象类型、ofs-delta/ref-delta、zlib 流边界。
//! 不做 delta 还原（由引擎负责），这里只切分出原始压缩块和元数据。

use super::reader::Reader;
use super::ObjType;
use flate2::{Decompress, FlushDecompress};
use sha1::{Digest, Sha1};
use std::io;

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// 对象在 pack 内的绝对偏移（header 起点）。
    pub offset: u64,
    pub kind: ObjType,
    /// header 里声明的解压后大小（对 delta 是 delta 指令字节数）。
    pub declared_size: u64,
    /// ofs-delta：base 绝对偏移（越界则为 None）。
    pub ofs_base: Option<u64>,
    /// ref-delta：base 对象 id。
    pub ref_base: Option<[u8; 20]>,
    /// 压缩数据在文件中的字节范围（zlib 流边界，含 adler32）。
    pub zlib_start: usize,
    pub zlib_end: usize,
    /// 解压后的原始字节；解压失败时为 None。
    pub inflated: Option<Vec<u8>>,
    /// 该对象条目的问题（大小欺骗、zlib 截断等）。
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_sha: Option<[u8; 20]>,
    pub trailer_ok: Option<bool>,
    pub errors: Vec<String>,
}

/// 从 `data[start..]` 解压恰好一个 zlib 流。
/// 返回 (流结束位置, 解压结果)；解压失败时结果为 None 并记录错误。
fn inflate_one(
    data: &[u8],
    start: usize,
    declared: u64,
    errors: &mut Vec<String>,
) -> io::Result<(usize, Option<Vec<u8>>)> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    loop {
        let iin = dec.total_in() as usize;
        let prev_out = dec.total_out() as usize;
        let mut tmp = [0u8; 16 * 1024];
        let status = dec.decompress(&data[start + iin..], &mut tmp, FlushDecompress::None);
        let produced = dec.total_out() as usize - prev_out;
        out.extend_from_slice(&tmp[..produced]);
        match status {
            Ok(flate2::Status::Ok) => {
                if out.len() > 300 * 1024 * 1024 {
                    errors.push(format!(
                        "inflated object at {} exceeds hard 300MiB cap (size bomb?)",
                        start
                    ));
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "inflated too large"));
                }
            }
            Ok(flate2::Status::StreamEnd) => break,
            Ok(_) => {}
            Err(e) => {
                errors.push(format!("zlib error at offset {}: {}", start, e));
                return Ok((dec.total_in() as usize, None));
            }
        }
    }
    let used = dec.total_in() as usize;
    if dec.total_in() as usize + start >= data.len() {
        errors.push(format!(
            "zlib stream at {} ran to end of file with no trailer/next object",
            start
        ));
    }
    if dec.total_out() != declared {
        errors.push(format!(
            "size spoof at offset {}: header declared {}, inflated {} bytes",
            start, declared, dec.total_out()
        ));
    }
    Ok((used, Some(out)))
}

pub fn parse(data: &[u8]) -> io::Result<PackFile> {
    let mut r = Reader::new(data);
    let mut errors = Vec::new();
    if r.take(4)? != b"PACK" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad pack magic"));
    }
    let version = r.u32()?;
    if version != 2 && version != 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported pack version {}", version),
        ));
    }
    let count = r.u32()?;

    let mut entries: Vec<PackEntry> = Vec::new();
    for _ in 0..count {
        let offset = r.pos as u64;
        let first = r.u8()?;
        let code = (first >> 4) & 0x7;
        let mut size = u64::from(first & 0x0f);
        let mut shift = 4u32;
        let mut cont = first & 0x80 != 0;
        while cont {
            let b = r.u8()?;
            size |= u64::from(b & 0x7f) << shift;
            shift += 7;
            cont = b & 0x80 != 0;
        }
        let kind = ObjType::from_pack_code(code).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown object type code {} at offset {}", code, offset),
            )
        })?;
        let mut ofs_base = None;
        let mut ref_base = None;
        if kind == ObjType::OfsDelta {
            let dist = r.ofs_delta_distance()?;
            if dist > offset {
                errors.push(format!(
                    "ofs-delta at {} distance {} points before pack start (base would be {})",
                    offset,
                    dist,
                    offset as i128 - dist as i128
                ));
            } else {
                ofs_base = Some(offset - dist);
            }
        } else if kind == ObjType::RefDelta {
            ref_base = Some(r.bytes20()?);
        }
        let zlib_start = r.pos;
        let mut entry_errors = Vec::new();
        let (used, inflated) = inflate_one(data, zlib_start, size, &mut entry_errors)?;
        let zlib_end = zlib_start + used;
        r.pos = zlib_end;
        if let Some(base) = ofs_base {
            if !entries.iter().any(|e: &PackEntry| e.offset == base) {
                errors.push(format!(
                    "ofs-delta at {} points to {} which is not an object header",
                    offset, base
                ));
            }
        }
        entries.push(PackEntry {
            offset,
            kind,
            declared_size: size,
            ofs_base,
            ref_base,
            zlib_start,
            zlib_end,
            inflated,
            errors: entry_errors,
        });
    }

    let (trailer_sha, trailer_ok) = if r.remaining() >= 20 {
        let sha = r.bytes20()?;
        let body = &data[..data.len() - 20];
        let mut h = Sha1::new();
        h.update(body);
        let calc: [u8; 20] = h.finalize().into();
        let ok = calc == sha;
        if !ok {
            errors.push("pack trailer checksum mismatch".to_string());
        }
        (Some(sha), Some(ok))
    } else {
        errors.push("pack missing 20-byte SHA-1 trailer".to_string());
        (None, None)
    };

    Ok(PackFile {
        version,
        count,
        entries,
        trailer_sha,
        trailer_ok,
        errors,
    })
}
