//! Git index v2 解析：fanout、oid 表、CRC32 表、offset 表（含 64 位大偏移表）。

use super::reader::Reader;
use sha1::{Digest, Sha1};
use std::io;

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct IdxFile {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha: Option<[u8; 20]>,
    pub idx_trailer_ok: Option<bool>,
    pub errors: Vec<String>,
}

pub fn parse(data: &[u8]) -> io::Result<IdxFile> {
    let mut errors = Vec::new();
    let mut r = Reader::new(data);
    let magic = r.u32()?;
    if magic != 0xff744f63 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not an idx v2 file (missing \\377tOc magic)",
        ));
    }
    let version = r.u32()?;
    if version != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported idx version {}", version),
        ));
    }
    let mut fanout = [0u32; 256];
    for slot in fanout.iter_mut() {
        *slot = r.u32()?;
    }
    let n = fanout[255] as usize;
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        oids.push(r.bytes20()?);
    }
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        crcs.push(r.u32()?);
    }
    let mut offs32 = Vec::with_capacity(n);
    for _ in 0..n {
        offs32.push(r.u32()?);
    }
    // 大偏移表的位置必须在读 offset 时记录：直接顺序解析。
    let mut offsets = Vec::with_capacity(n);
    for raw in offs32 {
        if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            // 大偏移表位于 32 位 offset 表之后；用绝对定位重读。
            let large_table = 8 + 256 * 4 + n * 20 + n * 4 + n * 4;
            let save = r.pos;
            r.pos = large_table + idx * 8;
            let big = r.u64()?;
            r.pos = save;
            offsets.push(big);
        } else {
            offsets.push(u64::from(raw));
        }
    }

    // fanout 一致性校验
    for i in 0..256 {
        let expect = oids.iter().filter(|o| o[0] as usize <= i).count() as u32;
        if fanout[i] != expect {
            errors.push(format!(
                "fanout[{}] inconsistent: table says {} but sorted oids imply {}",
                i, fanout[i], expect
            ));
            break;
        }
    }
    // oid 必须排序
    for w in oids.windows(2) {
        if w[0] >= w[1] {
            errors.push(format!(
                "idx oid table not strictly sorted at {} / {}",
                hex::encode(w[0]),
                hex::encode(w[1])
            ));
            break;
        }
    }

    let entries = oids
        .into_iter()
        .zip(crcs)
        .zip(offsets)
        .map(|((oid, crc32), offset)| IdxEntry { oid, crc32, offset })
        .collect();

    // 尾部：pack sha + idx sha（idx sha 覆盖前面全部内容）
    let (pack_sha, idx_trailer_ok) = if r.remaining() >= 40 {
        let pack_sha = r.bytes20()?;
        let idx_sha = r.bytes20()?;
        let mut h = Sha1::new();
        h.update(&data[..data.len() - 20]);
        let calc: [u8; 20] = h.finalize().into();
        let ok = calc == idx_sha;
        if !ok {
            errors.push("idx trailer checksum mismatch".to_string());
        }
        (Some(pack_sha), Some(ok))
    } else {
        errors.push("idx missing trailing sha fields".to_string());
        (None, None)
    };

    Ok(IdxFile {
        fanout,
        entries,
        pack_sha,
        idx_trailer_ok,
        errors,
    })
}

/// 校验 idx 里登记的 CRC32 是否等于对应 pack 条目压缩数据的 CRC。
/// `pack_bytes` 为整个 pack；返回 (offset, expected, actual) 的不匹配列表。
pub fn verify_crcs(idx: &IdxFile, pack_bytes: &[u8], ranges: &[(u64, usize, usize)]) -> Vec<(u64, u32, u32)> {
    let mut bad = Vec::new();
    for e in &idx.entries {
        if let Some((_, start, end)) = ranges.iter().find(|(off, _, _)| *off == e.offset) {
            if *end <= pack_bytes.len() {
                let actual = crc32fast::hash(&pack_bytes[*start..*end]);
                if actual != e.crc32 {
                    bad.push((e.offset, e.crc32, actual));
                }
            } else {
                bad.push((e.offset, e.crc32, 0));
            }
        }
    }
    bad
}

/// 供调用方直接使用的 fanout 摘要。
pub fn fanout_summary(fanout: &[u32; 256]) -> Vec<(u8, u32)> {
    fanout
        .iter()
        .enumerate()
        .filter(|(_, v)| **v > 0)
        .map(|(i, v)| (i as u8, *v))
        .collect()
}

/// 忽略未使用导入警告占位（Reader 在解析中实际使用）。
#[allow(dead_code)]
fn _use_reader(_: Reader<'_>) {}
