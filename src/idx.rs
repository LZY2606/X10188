use crate::error::{Error, ErrorCode, R};
use crate::model::IdxInfo;

pub fn parse_idx(buf: &[u8]) -> R<IdxInfo> {
    if buf.len() < 8 {
        return Err(Error::new(ErrorCode::IdxTruncated, "idx too short"));
    }
    if &buf[0..4] == b"\xfftOc" {
        parse_v2(buf)
    } else {
        parse_v1(buf)
    }
}

fn be_u32(buf: &[u8], at: usize) -> u32 {
    u32::from_be_bytes(buf[at..at + 4].try_into().unwrap())
}

fn parse_v2(buf: &[u8]) -> R<IdxInfo> {
    let version = be_u32(buf, 4);
    if version != 2 {
        return Err(Error::new(ErrorCode::IdxUnsupportedVersion, format!("idx v{}", version)));
    }
    let fanout_start = 8;
    let n = be_u32(buf, fanout_start + 255 * 4) as usize;
    let mut p = fanout_start + 256 * 4;
    let need = p + n * 20 + n * 4 + n * 4 + 40;
    if buf.len() < need {
        return Err(Error::new(
            ErrorCode::IdxTruncated,
            format!("idx needs {} bytes, has {}", need, buf.len()),
        ));
    }
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&buf[p..p + 20]);
        oids.push(oid);
        p += 20;
    }
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        crcs.push(be_u32(buf, p));
        p += 4;
    }
    let mut offsets = Vec::with_capacity(n);
    for _ in 0..n {
        let raw = be_u32(buf, p);
        p += 4;
        if raw & 0x8000_0000 != 0 {
            return Err(Error::new(ErrorCode::IdxUnsupportedVersion, "64-bit offset tables not supported"));
        }
        offsets.push(raw as u64);
    }
    let mut pack_sha = [0u8; 20];
    pack_sha.copy_from_slice(&buf[p..p + 20]);
    p += 20;
    let mut idx_sha = [0u8; 20];
    idx_sha.copy_from_slice(&buf[p..p + 20]);

    let records = (0..n)
        .map(|i| crate::model::IdxRecord { oid: oids[i], crc: crcs[i], offset: offsets[i] })
        .collect();
    Ok(IdxInfo { version, records, pack_sha, idx_sha })
}

/// v1 idx: 256 fanout u32, then n * (offset u32, oid 20).
fn parse_v1(buf: &[u8]) -> R<IdxInfo> {
    let n = be_u32(buf, 255 * 4) as usize;
    let table = 256 * 4;
    let need = table + n * 24 + 40;
    if buf.len() < need {
        return Err(Error::new(ErrorCode::IdxTruncated, "v1 idx truncated"));
    }
    let mut p = table;
    let mut pairs = Vec::with_capacity(n);
    for _ in 0..n {
        let offset = be_u32(buf, p) as u64;
        p += 4;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&buf[p..p + 20]);
        p += 20;
        pairs.push((offset, oid));
    }
    pairs.sort_by_key(|(o, _)| *o);
    let mut pack_sha = [0u8; 20];
    pack_sha.copy_from_slice(&buf[p..p + 20]);
    p += 20;
    let mut idx_sha = [0u8; 20];
    idx_sha.copy_from_slice(&buf[p..p + 20]);
    let records = pairs
        .into_iter()
        .map(|(offset, oid)| crate::model::IdxRecord { oid, crc: 0, offset })
        .collect();
    Ok(IdxInfo { version: 1, records, pack_sha, idx_sha })
}
