//! pack idx v2 解析：fanout、oid/crc/offset 表与 SHA1 交叉校验。

use crate::encoding::{sha1_bytes, Crc32};
use crate::types::Evidence;

#[derive(Debug, Clone)]
pub struct IdxRecord {
    pub oid: [u8; 20],
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct ParsedIdx {
    pub fanout: [u32; 256],
    pub records: Vec<IdxRecord>,
    /// idx 自身 trailer SHA1 是否通过
    pub idx_checksum_ok: bool,
    /// idx 记录的 pack SHA1 是否与给定 pack 内容一致
    pub pack_checksum_ok: Option<bool>,
    pub evidences: Vec<Evidence>,
}

pub fn parse_idx(data: &[u8], pack: Option<&[u8]>) -> Option<ParsedIdx> {
    if data.len() < 8 || &data[..4] != b"\xfftOc" {
        return None;
    }
    let version = u32::from_be_bytes(data[4..8].try_into().ok()?);
    let mut evidences = Vec::new();
    if version != 2 {
        evidences.push(Evidence::new(
            "unsupported_idx_version",
            format!("仅支持 idx v2，实际 v{version}"),
        ));
        return Some(ParsedIdx {
            fanout: [0u32; 256],
            records: Vec::new(),
            idx_checksum_ok: false,
            pack_checksum_ok: None,
            evidences,
        });
    }

    let fanout_start = 8;
    let mut fanout = [0u32; 256];
    for (i, slot) in fanout.iter_mut().enumerate() {
        let s = fanout_start + i * 4;
        *slot = u32::from_be_bytes(data.get(s..s + 4)?.try_into().ok()?);
    }
    // fanout 必须单调不减
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            evidences.push(Evidence::new(
                "fanout_not_monotonic",
                format!("fanout[{i}] 小于 fanout[{}]，fanout 损坏", i - 1),
            ));
        }
    }
    let n = fanout[255] as usize;

    let oid_start = fanout_start + 256 * 4;
    let crc_start = oid_start + n * 20;
    let off_start = crc_start + n * 4;
    let _8_offsets_start = off_start + n * 4;

    let mut records = Vec::with_capacity(n);
    for i in 0..n {
        let oid: [u8; 20] = data
            .get(oid_start + i * 20..oid_start + i * 20 + 20)?
            .try_into()
            .ok()?;
        let crc32 = u32::from_be_bytes(
            data.get(crc_start + i * 4..crc_start + i * 4 + 4)?
                .try_into()
                .ok()?,
        );
        let off_word = u32::from_be_bytes(
            data.get(off_start + i * 4..off_start + i * 4 + 4)?
                .try_into()
                .ok()?,
        );
        let offset = if off_word & 0x8000_0000 != 0 {
            let idx = (off_word & 0x7fff_ffff) as usize;
            let s = _8_offsets_start + idx * 8;
            u64::from_be_bytes(data.get(s..s + 8)?.try_into().ok()?)
        } else {
            off_word as u64
        };
        // fanout 一致性：每个 oid 必须落在 fanout 给出的区间内
        let first = oid[0] as usize;
        let lo = if first == 0 { 0 } else { fanout[first - 1] } as usize;
        let hi = fanout[first] as usize;
        if i < lo || i >= hi {
            evidences.push(Evidence::new(
                "fanout_record_inconsistent",
                format!("第 {i} 条 oid 首字节 {first:#04x} 与 fanout 区间 [{lo},{hi}) 不符"),
            ));
        }
        records.push(IdxRecord { oid, crc32, offset });
    }

    // trailer：pack-sha1(20) + idx-sha1(20)，统一按文件尾部 40 字节定位。
    let end = data.len();
    let idx_checksum_ok = end >= 40 && {
        let body_end = end - 20;
        sha1_bytes(&data[..body_end]) == data[body_end..end]
    };
    let pack_checksum_ok = if end >= 40 {
        let want = &data[end - 40..end - 20];
        Some(pack.map(|p| p.len() >= 20 && want == &p[p.len() - 20..]).unwrap_or(true))
    } else {
        None
    };
    if !idx_checksum_ok {
        evidences.push(Evidence::new("idx_checksum_mismatch", "idx 尾部 SHA1 与 idx 内容不一致"));
    }
    if pack_checksum_ok == Some(false) {
        evidences.push(Evidence::new(
            "idx_pack_mismatch",
            "idx 记录的 pack SHA1 与导入的 pack 不一致（index 与 pack 不配套）",
        ));
    }

    Some(ParsedIdx {
        fanout,
        records,
        idx_checksum_ok,
        pack_checksum_ok,
        evidences,
    })
}

/// 用 idx 的 CRC32 校验 pack entry 的压缩字节。
pub fn crc_of_entry(pack: &[u8], zlib_offset: u64, zlib_len: u64) -> Option<u32> {
    let s = zlib_offset as usize;
    let e = s.checked_add(zlib_len as usize)?;
    let bytes = pack.get(s..e)?;
    let mut c = Crc32::new();
    c.update(bytes);
    Some(c.finish())
}
