//! .idx 文件解析：fanout、oid 表、crc32 表与 32/64 位 offset 表。

use super::pack::ParsedPack;
use super::{sha1_bytes, Oid};

#[derive(Clone, Debug)]
pub struct IdxEntry {
    pub oid: Oid,
    pub offset: u64,
    /// index 中记录的 CRC32（仅 v2）。
    pub crc32: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct ParsedIdx {
    pub version: u8,
    pub entries: Vec<IdxEntry>,
    /// fanout[255]。
    pub fanout_total: u32,
    pub stored_pack_checksum: Option<Oid>,
    pub stored_idx_checksum: Option<Oid>,
    pub computed_idx_checksum: Option<Oid>,
    pub idx_checksum_ok: bool,
    pub fanout_errors: Vec<String>,
    pub fatal_error: Option<String>,
}

pub fn parse_idx(data: &[u8]) -> ParsedIdx {
    let mut idx = ParsedIdx {
        version: 0,
        entries: Vec::new(),
        fanout_total: 0,
        stored_pack_checksum: None,
        stored_idx_checksum: None,
        computed_idx_checksum: None,
        idx_checksum_ok: false,
        fanout_errors: Vec::new(),
        fatal_error: None,
    };

    let mut pos: usize = 0;
    let (v2, oid_table) = if data.len() >= 8 && &data[0..4] == b"\xfftOc" {
        let ver = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if ver != 2 {
            idx.fatal_error = Some(format!("不支持的 idx 版本 v{}", ver));
            return idx;
        }
        idx.version = 2;
        pos = 8;
        true
    } else {
        idx.version = 1;
        pos = 0;
        false
    };

    if data.len() < pos + 256 * 4 {
        idx.fatal_error = Some("idx 短于 fanout 表长度".to_string());
        return idx;
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32::from_be_bytes([
            data[pos + i * 4],
            data[pos + i * 4 + 1],
            data[pos + i * 4 + 2],
            data[pos + i * 4 + 3],
        ]);
    }
    pos += 256 * 4;
    idx.fanout_total = fanout[255];

    let n = fanout[255] as usize;
    // fanout 必须单调不减，且每个桶数量不超过总数量。
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            idx.fanout_errors
                .push(format!("fanout[{}] < fanout[{}]（{} < {}），fanout 表非法", i, i - 1, fanout[i], fanout[i - 1]));
        }
    }

    if data.len() < pos + n * 20 {
        idx.fatal_error = Some(format!("idx 缺少 {} 个 oid 表项", n));
        return idx;
    }
    let mut oids = Vec::with_capacity(n);
    for i in 0..n {
        let mut o = Oid([0u8; 20]);
        o.0.copy_from_slice(&data[pos + i * 20..pos + (i + 1) * 20]);
        oids.push(o);
    }
    pos += n * 20;

    let mut crcs: Vec<Option<u32>> = vec![None; n];
    if v2 {
        if data.len() < pos + n * 4 {
            idx.fatal_error = Some("idx 缺少 crc32 表".to_string());
            return idx;
        }
        for i in 0..n {
            crcs[i] = Some(u32::from_be_bytes([
                data[pos + i * 4],
                data[pos + i * 4 + 1],
                data[pos + i * 4 + 2],
                data[pos + i * 4 + 3],
            ]));
        }
        pos += n * 4;
    }

    if data.len() < pos + n * 4 {
        idx.fatal_error = Some("idx 缺少 offset 表".to_string());
        return idx;
    }
    let mut offsets: Vec<u64> = Vec::with_capacity(n);
    let mut large_slots: Vec<(usize, u64)> = Vec::new();
    for i in 0..n {
        let v = u32::from_be_bytes([
            data[pos + i * 4],
            data[pos + i * 4 + 1],
            data[pos + i * 4 + 2],
            data[pos + i * 4 + 3],
        ]);
        if v & 0x8000_0000 != 0 {
            large_slots.push((i, (v & 0x7fff_ffff) as u64));
        } else {
            offsets.push(v as u64);
        }
    }
    pos += n * 4;

    // 64 位偏移表（v2，槽位按顺序对应）
    for (slot_idx, large_idx) in large_slots {
        let at = pos + large_idx as usize * 8;
        if data.len() < at + 8 {
            idx.fatal_error = Some(format!("idx 64 位偏移表缺项（slot {}）", slot_idx));
            return idx;
        }
        let v = u64::from_be_bytes([
            data[at], data[at + 1], data[at + 2], data[at + 3],
            data[at + 4], data[at + 5], data[at + 6], data[at + 7],
        ]);
        offsets.push(v);
        if slot_idx >= n {
            // 不可能，但保护一下
            continue;
        }
    }
    // 上面 large_slots 按升序追加，offsets 顺序与槽位不一致，需重建：
    let mut final_offsets: Vec<u64> = vec![0; n];
    let mut small_iter = 0usize;
    let mut large_map: std::collections::HashMap<usize, u64> = std::collections::HashMap::new();
    // 重新解析以建立正确顺序
    let off_table_start = if v2 {
        8 + 256 * 4 + n * 20 + n * 4
    } else {
        256 * 4 + n * 20
    };
    let mut large_order: Vec<(usize, u64)> = Vec::new();
    for i in 0..n {
        let at = off_table_start + i * 4;
        let v = u32::from_be_bytes([
            data[at], data[at + 1], data[at + 2], data[at + 3],
        ]);
        if v & 0x8000_0000 != 0 {
            large_order.push((i, (v & 0x7fff_ffff) as u64));
        } else {
            final_offsets[i] = v as u64;
        }
    }
    let large_table_start = off_table_start + n * 4;
    let mut lpos = large_table_start;
    for (slot, _idx_of_large) in &large_order {
        if data.len() < lpos + 8 {
            idx.fatal_error = Some("idx 64 位偏移表不完整".to_string());
            return idx;
        }
        let v = u64::from_be_bytes([
            data[lpos], data[lpos + 1], data[lpos + 2], data[lpos + 3],
            data[lpos + 4], data[lpos + 5], data[lpos + 6], data[lpos + 7],
        ]);
        large_map.insert(*slot, v);
        lpos += 8;
    }
    let _ = (small_iter, offsets, large_slots);
    for (slot, v) in large_map {
        final_offsets[slot] = v;
    }

    // trailer: pack checksum (20) + idx checksum (20)，仅 v2 强制校验
    if v2 {
        if data.len() < lpos + 40 {
            idx.fatal_error = Some("idx 缺少尾部校验和".to_string());
            return idx;
        }
        let mut pc = Oid([0u8; 20]);
        pc.0.copy_from_slice(&data[data.len() - 40..data.len() - 20]);
        let mut ic = Oid([0u8; 20]);
        ic.0.copy_from_slice(&data[data.len() - 20..]);
        idx.stored_pack_checksum = Some(pc);
        idx.stored_idx_checksum = Some(ic);
        idx.computed_idx_checksum = Some(sha1_bytes(&data[..data.len() - 20]));
        idx.idx_checksum_ok = idx.computed_idx_checksum == idx.stored_idx_checksum;
    }

    for i in 0..n {
        idx.entries.push(IdxEntry {
            oid: oids[i],
            offset: final_offsets[i],
            crc32: crcs[i],
        });
    }
    idx
}

/// 校验 index 与 pack 是否配套：checksum、offset 集合、CRC32。
/// 返回错误证据列表（空表示配套）。
pub fn cross_check(idx: &ParsedIdx, pack: &ParsedPack) -> Vec<String> {
    let mut errs = Vec::new();
    if let (Some(pc), true) = (idx.stored_pack_checksum, idx.version == 2) {
        if pc != pack.stored_checksum {
            errs.push(format!(
                "index 记录的 pack checksum {} 与 pack 自带 {} 不一致（index 与 pack 不配套）",
                pc.short(),
                pack.stored_checksum.short()
            ));
        }
    }
    let pack_by_offset: std::collections::HashMap<u64, &super::pack::RawEntry> =
        pack.entries.iter().map(|e| (e.offset, e)).collect();
    for ie in &idx.entries {
        match pack_by_offset.get(&ie.offset) {
            None => errs.push(format!(
                "index 条目 {} 指向偏移 {}，pack 中无此对象起点",
                ie.oid.short(),
                ie.offset
            )),
            Some(pe) => {
                if let (Some(ic), Some(pc)) = (ie.crc32, pe.crc32) {
                    if ic != pc {
                        errs.push(format!(
                            "偏移 {}（{}）CRC32 不一致：index={:08x} pack={:08x}",
                            ie.offset,
                            ie.oid.short(),
                            ic,
                            pc
                        ));
                    }
                }
            }
        }
    }
    if idx.entries.len() != pack.entries.len() {
        errs.push(format!(
            "对象数量不一致：index {} 个，pack {} 个",
            idx.entries.len(),
            pack.entries.len()
        ));
    }
    errs
}
