//! pack index v2 解析：magic、fanout(256)、oid 表、crc32 表、offset 表。

use super::{oid_hex, Error, Result};

#[derive(Clone, Debug)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Clone, Debug)]
pub struct IdxInfo {
    pub version: u32,
    pub num_objects: u32,
    /// 256 项 fanout；fanout[i] = oid 首字节 <= i 的对象数。
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxInfo> {
    if data.len() < 8 {
        return Err(Error::Idx("文件不足 8 字节".into()));
    }
    let version;
    let mut pos = 0usize;
    if &data[0..4] == b"\xfftOc" {
        version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if version != 2 {
            return Err(Error::Idx(format!("不支持的 idx 版本 {}", version)));
        }
        pos = 8;
    } else {
        version = 1;
        pos = 0;
    }
    if version != 2 {
        return Err(Error::Idx("仅支持 idx v2（带 \\377tOc 头）".into()));
    }

    if pos + 256 * 4 > data.len() {
        return Err(Error::Idx("fanout 表不完整".into()));
    }
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        fanout.push(u32::from_be_bytes([
            data[pos + i * 4],
            data[pos + i * 4 + 1],
            data[pos + i * 4 + 2],
            data[pos + i * 4 + 3],
        ]));
    }
    pos += 256 * 4;
    let n = fanout[255] as usize;

    if pos + n * 20 > data.len() {
        return Err(Error::Idx("oid 表不完整".into()));
    }
    let mut oids = Vec::with_capacity(n);
    for i in 0..n {
        let mut o = [0u8; 20];
        o.copy_from_slice(&data[pos + i * 20..pos + i * 20 + 20]);
        oids.push(o);
    }
    pos += n * 20;

    if pos + n * 4 > data.len() {
        return Err(Error::Idx("crc32 表不完整".into()));
    }
    let mut crcs = Vec::with_capacity(n);
    for i in 0..n {
        crcs.push(u32::from_be_bytes([
            data[pos + i * 4],
            data[pos + i * 4 + 1],
            data[pos + i * 4 + 2],
            data[pos + i * 4 + 3],
        ]));
    }
    pos += n * 4;

    if pos + n * 4 > data.len() {
        return Err(Error::Idx("offset 表不完整".into()));
    }
    let mut raw_offsets = Vec::with_capacity(n);
    for i in 0..n {
        let v = u32::from_be_bytes([
            data[pos + i * 4],
            data[pos + i * 4 + 1],
            data[pos + i * 4 + 2],
            data[pos + i * 4 + 3],
        ]);
        raw_offsets.push(v);
    }
    pos += n * 4;

    // 大偏移表（8 字节表项）。高位被设置的 offset 指向该表的索引。
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let raw = raw_offsets[i];
        let offset = if raw & 0x8000_0000 != 0 {
            let big_idx = (raw & 0x7fff_ffff) as usize;
            let p = pos + big_idx * 8;
            if p + 8 > data.len() {
                return Err(Error::Idx(format!(
                    "对象 {} 的 64 位大偏移表项不完整",
                    oid_hex(&oids[i])
                )));
            }
            u64::from_be_bytes([
                data[p], data[p + 1], data[p + 2], data[p + 3],
                data[p + 4], data[p + 5], data[p + 6], data[p + 7],
            ])
        } else {
            raw as u64
        };
        entries.push(IdxEntry {
            oid: oids[i],
            offset,
            crc32: crcs[i],
        });
    }

    Ok(IdxInfo {
        version,
        num_objects: n as u32,
        fanout,
        entries,
    })
}
