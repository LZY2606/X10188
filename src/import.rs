use std::path::Path;

use rusqlite::{params, Connection};


use crate::index::ParsedIndex;
use crate::loose::ParsedLoose;
use crate::oid::Oid;
use crate::pack::ParsedPack;

#[derive(Debug, Clone)]
pub struct ImportReport {
    pub source_id: i64,
    pub kind: String,
    pub candidates: usize,
    pub fatal: Option<String>,
    pub note: Option<String>,
}

pub fn sniff_kind(buf: &[u8]) -> &'static str {
    if buf.len() >= 4 && &buf[0..4] == b"PACK" {
        "pack"
    } else if buf.len() >= 8 && &buf[0..4] == b"\xfftOc" {
        "index"
    } else if buf.len() >= 256 * 4 + 40 && looks_like_idx_v1(buf) {
        "index"
    } else {
        "loose"
    }
}

fn looks_like_idx_v1(buf: &[u8]) -> bool {
    // fanout 单调不减且最后一个桶是“合理”的小对象数；启发式。
    let mut prev = 0u32;
    for i in 0..256 {
        let o = i * 4;
        let v = u32::from_be_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        if v < prev {
            return false;
        }
        prev = v;
    }
    let n = prev as usize;
    n > 0 && 256 * 4 + n * 24 + 40 == buf.len()
}

pub fn store_file(files_dir: &Path, fp: &str, orig: &str, buf: &[u8]) -> std::io::Result<String> {
    std::fs::create_dir_all(files_dir)?;
    let safe: String = orig
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' { c } else { '_' })
        .collect();
    let name = format!("{}_{}", &fp[..12], safe);
    let path = files_dir.join(&name);
    std::fs::write(&path, buf)?;
    Ok(name)
}

pub fn insert_source(
    conn: &Connection,
    kind: &str,
    filename: &str,
    stored: &str,
    byte_len: usize,
    fp: &str,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO sources(kind, filename, stored_path, byte_len, sha256)
         VALUES (?1,?2,?3,?4,?5)",
        params![kind, filename, stored, byte_len as i64, fp],
    )?;
    Ok(conn.last_insert_rowid())
}

fn next_ord(conn: &Connection) -> i64 {
    conn.query_row("SELECT COALESCE(MAX(ord),0)+1 FROM candidates", [], |r| {
        r.get::<_, i64>(0)
    })
    .unwrap_or(1)
}

fn insert_fanout(conn: &Connection, source_id: i64, kind: &str, json: &str) {
    let _ = conn.execute(
        "INSERT INTO fanout(source_id, kind, cumulative_json) VALUES (?1,?2,?3)",
        params![source_id, kind, json],
    );
}

fn pack_layout_fanout(entries: &[crate::pack::ParsedEntry], pack_len: u64) -> String {
    // 按对象起始偏移映射到 256 个字节范围桶，累计计数。
    let mut buckets = vec![0u32; 256];
    let span = pack_len.max(1);
    for e in entries {
        let b = ((e.offset as u128 * 256 / span as u128) as usize).min(255);
        buckets[b] += 1;
    }
    let mut cum = 0u32;
    let cumulative: Vec<u32> = buckets
        .iter()
        .map(|x| {
            cum += x;
            cum
        })
        .collect();
    serde_json::to_string(&cumulative).unwrap_or_else(|_| "[]".to_string())
}

/// 将解析后的 pack 入库。返回 (source_id, 候选 offset->cand_id, 候选 oid->cand_id)。
pub fn persist_pack(
    conn: &Connection,
    source_id: i64,
    parsed: &ParsedPack,
    index: Option<&ParsedIndex>,
) {
    let trailer = parsed.trailer_sha.hex();
    let computed = parsed.computed_sha.hex();
    let checksum_ok = parsed.checksum_ok as i64;
    let (status, note) = if let Some(f) = &parsed.fatal {
        ("fatal", Some(f.to_string()))
    } else if !parsed.checksum_ok {
        (
            "fatal",
            Some(
                crate::error::PError::ChecksumMismatch {
                    expected: trailer.clone(),
                    actual: computed.clone(),
                }
                .to_string(),
            ),
        )
    } else {
        ("ok", None)
    };
    let idx_pack = index.map(|i| i.pack_checksum.hex());
    conn.execute(
        "UPDATE sources SET pack_checksum=?1, idx_pack_checksum=?2, status=?3, note=?4 WHERE id=?5",
        params![computed, idx_pack, status, note, source_id],
    )
    .ok();
    let _ = checksum_ok;

    // 用 index 的 (offset -> (oid,crc)) 建立映射
    let mut by_offset: std::collections::BTreeMap<u64, (Oid, Option<u32>)> =
        std::collections::BTreeMap::new();
    if let Some(idx) = index {
        for e in &idx.entries {
            by_offset.insert(e.offset, (e.oid, e.crc32));
        }
    }

    let mut ord = next_ord(conn);
    for entry in &parsed.entries {
        let idx_info = by_offset.get(&entry.offset);
        let claim = idx_info.map(|(o, _)| o.hex());
        let idx_crc = idx_info.and_then(|(_, c)| *c);
        let (pe_code, pe_msg) = match &entry.error {
            Some(e) => (Some(e.code().to_string()), Some(e.to_string())),
            None => (None, None),
        };
        conn.execute(
            "INSERT INTO candidates(
                source_id, origin, pack_offset, data_start, header_len, zlib_consumed,
                compressed, etype, kind, declared_size, inflated_size, payload,
                claim_oid, idx_crc, base_ofs, base_ref_oid,
                parse_error_code, parse_error, ord
             ) VALUES (?1,'pack',?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
            params![
                source_id,
                entry.offset as i64,
                entry.data_start as i64,
                entry.header_len as i64,
                entry.zlib_consumed as i64,
                entry.compressed,
                entry.etype.label(),
                entry.kind.map(|k| k.word()),
                entry.declared_size as i64,
                entry.inflated_size as i64,
                entry.payload,
                claim,
                idx_crc.map(|c| c as i64),
                entry.base_offset.map(|o| o as i64),
                entry.base_ref.map(|o| o.hex()),
                pe_code,
                pe_msg,
                ord
            ],
        )
        .ok();
        ord += 1;
    }

    insert_fanout(conn, source_id, "pack_layout", &pack_layout_fanout(&parsed.entries, 0));
}

pub fn persist_index_fanout(conn: &Connection, source_id: i64, idx: &ParsedIndex) {
    let json = serde_json::to_string(&idx.fanout.cumulative).unwrap_or_else(|_| "[]".to_string());
    insert_fanout(conn, source_id, "idx256", &json);
}

pub fn persist_loose(
    conn: &Connection,
    source_id: i64,
    pl: &ParsedLoose,
    path_oid: Option<&str>,
) {
    let ord = next_ord(conn);
    let claim = pl.computed_oid.hex();
    let verified = path_oid.map(|p| p == claim).unwrap_or(true) as i64;
    conn.execute(
        "INSERT INTO candidates(
            source_id, origin, etype, kind, declared_size, inflated_size, payload,
            claim_oid, oid_verified, zlib_consumed, resolved_kind, ord, status
         ) VALUES (?1,'loose',?2,?2,?3,?4,?5,?6,?7,?8,?2,?9,'resolved')",
        params![
            source_id,
            pl.kind.word(),
            pl.declared_size as i64,
            pl.content.len() as i64,
            pl.content,
            claim,
            verified,
            pl.zlib_consumed as i64,
            ord
        ],
    )
    .ok();
}

