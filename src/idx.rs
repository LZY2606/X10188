//! Git index v2 解析。v1（无 magic）按 fanout 也能粗略识别，但本实现重点支持 v2。
//!
//! 布局（大端）：
//!   magic `\xfftOc`(4) + version=2(4)
//!   fanout[256] (256*4)
//!   sha1 名字表 (N*20)
//!   crc32 表   (N*4)
//!   offset 表  (N*4)，最高位为 1 表示 8 字节大偏移索引
//!   large offsets (M*8)
//!   pack sha1 (20) + idx sha1 (20)

use crate::types::{Evidence, IdxEntry, IdxReport};

pub const IDX_V2_MAGIC: &[u8; 4] = b"\xfftOc";

pub fn looks_like_idx_v2(buf: &[u8]) -> bool {
    buf.len() >= 8 && &buf[0..4] == IDX_V2_MAGIC && &buf[4..8] == 2u32.to_be_bytes()
}

fn be_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(buf[at..at + 4].try_into().unwrap())
}

pub fn parse_idx_v2(buf: &[u8]) -> IdxReport {
    let mut ev = Vec::new();
    if !looks_like_idx_v2(buf) {
        ev.push(Evidence::new("bad_idx_magic", "不是 index v2（magic \\377tOc / version 2 不符）", Some(0), Some(8)));
        return IdxReport {
            version: 0,
            fanout: vec![],
            entries: vec![],
            pack_checksum: None,
            idx_checksum: None,
            evidence: ev,
        };
    }

    let fanout: Vec<u32> = (0..256).map(|i| be_u32(buf, 8 + i * 4)).collect();
    let n = fanout[255] as usize;

    // fanout 必须单调不减。
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            ev.push(Evidence::new(
                "bad_fanout",
                format!("fanout[{i}]={} 小于 fanout[{}]={}", fanout[i], i - 1, fanout[i - 1]),
                Some((8 + i * 4) as u64),
                Some(4),
            ));
        }
    }

    let mut pos = 8 + 256 * 4;
    let need_names = pos + n * 20;
    if buf.len() < need_names {
        ev.push(Evidence::new("truncated_idx_names", "oid 名字表被截断", Some(pos as u64), None));
        return IdxReport { version: 2, fanout, entries: vec![], pack_checksum: None, idx_checksum: None, evidence: ev };
    }
    let mut oids = Vec::with_capacity(n);
    for i in 0..n {
        oids.push(hex::encode(&buf[pos + i * 20..pos + (i + 1) * 20]));
    }
    pos = need_names;

    let need_crc = pos + n * 4;
    if buf.len() < need_crc {
        ev.push(Evidence::new("truncated_idx_crc", "crc32 表被截断", Some(pos as u64), None));
        return IdxReport { version: 2, fanout, entries: vec![], pack_checksum: None, idx_checksum: None, evidence: ev };
    }
    let mut crcs = Vec::with_capacity(n);
    for i in 0..n {
        crcs.push(be_u32(buf, pos + i * 4));
    }
    pos = need_crc;

    let need_off = pos + n * 4;
    if buf.len() < need_off + 40 {
        ev.push(Evidence::new("truncated_idx_offsets", "offset 表或尾部校验和被截断", Some(pos as u64), None));
        return IdxReport { version: 2, fanout, entries: vec![], pack_checksum: None, idx_checksum: None, evidence: ev };
    }
    let mut off32 = Vec::with_capacity(n);
    let mut large_idx = Vec::new();
    for i in 0..n {
        let v = be_u32(buf, pos + i * 4);
        off32.push(v);
        if v & 0x8000_0000 != 0 {
            large_idx.push((i, (v & 0x7fff_ffff) as usize));
        }
    }
    pos = need_off;

    let m = large_idx.iter().map(|&(_, idx)| idx + 1).max().unwrap_or(0);
    let need_large = pos + m * 8;
    if m > 0 && buf.len() < need_large + 40 {
        ev.push(Evidence::new("truncated_idx_large_offsets", "64 位大偏移表被截断", Some(pos as u64), None));
        return IdxReport { version: 2, fanout, entries: vec![], pack_checksum: None, idx_checksum: None, evidence: ev };
    }
    let large: Vec<u64> = (0..m)
        .map(|i| u64::from_be_bytes(buf[pos + i * 8..pos + (i + 1) * 8].try_into().unwrap()))
        .collect();
    let after_large = pos + m * 8;

    let entries: Vec<IdxEntry> = (0..n)
        .map(|i| {
            let raw = off32[i];
            let offset = if raw & 0x8000_0000 != 0 {
                let li = (raw & 0x7fff_ffff) as usize;
                large.get(li).copied().unwrap_or(u64::MAX)
            } else {
                raw as u64
            };
            IdxEntry { offset, oid: oids[i].clone(), crc32: crcs[i] }
        })
        .collect();

    if buf.len() < after_large + 40 {
        ev.push(Evidence::new("truncated_idx_trailer", "缺少 pack/idx 校验和", Some(after_large as u64), None));
        return IdxReport { version: 2, fanout, entries, pack_checksum: None, idx_checksum: None, evidence: ev };
    }
    let pack_checksum = hex::encode(&buf[after_large..after_large + 20]);
    let idx_checksum = hex::encode(&buf[after_large + 20..after_large + 40]);

    let computed_idx = crate::hash::sha1_hex(&buf[..after_large + 20]);
    if computed_idx != idx_checksum {
        ev.push(Evidence::new(
            "idx_checksum_mismatch",
            format!("idx 校验和 {idx_checksum} 与重算 {computed_idx} 不符"),
            Some((after_large + 20) as u64),
            Some(20),
        ));
    }

    // 名字表应当严格排序（fanout 语义）。
    for i in 1..n {
        if oids[i - 1] >= oids[i] {
            ev.push(Evidence::new("idx_names_not_sorted", format!("名字表在第 {i} 项未严格递增"), None, None));
            break;
        }
    }

    IdxReport { version: 2, fanout, entries, pack_checksum: Some(pack_checksum), idx_checksum: Some(idx_checksum), evidence: ev }
}
