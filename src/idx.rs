//! Git pack index (v2) parsing: magic, fanout table, oid/crc/offset tables.

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct IdxParse {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: String,
    pub idx_checksum: String,
    pub checksum_ok: bool,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxParse, String> {
    if data.len() < 4 + 4 + 256 * 4 + 20 {
        return Err("文件太小，不是 v2 index".into());
    }
    if &data[0..4] != b"\xfftOc" {
        return Err("缺少 index v2 魔数 (\\377tOc)；v1 或未知格式不受支持".into());
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        return Err(format!("不支持的 index 版本 {version}"));
    }
    let mut fanout = [0u32; 256];
    let mut pos = 8usize;
    for slot in fanout.iter_mut() {
        *slot = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4;
    }
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            return Err(format!("fanout 表非单调: fanout[{i}] < fanout[{}]", i - 1));
        }
    }
    let n = fanout[255] as usize;
    let need = pos + n * 20 + n * 4 + n * 4 + 20 + 20;
    if data.len() < need {
        return Err(format!(
            "index 截断: fanout 声明 {n} 个对象需要至少 {need} 字节，实际 {}",
            data.len()
        ));
    }
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        oids.push(hex::encode(&data[pos..pos + 20]));
        pos += 20;
    }
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        crcs.push(u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]));
        pos += 4;
    }
    let mut raw_offsets = Vec::with_capacity(n);
    for _ in 0..n {
        raw_offsets.push(u32::from_be_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]));
        pos += 4;
    }
    let large_table_start = pos;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let raw = raw_offsets[i];
        let offset = if raw & 0x8000_0000 != 0 {
            let idx64 = (raw & 0x7fff_ffff) as usize;
            let p = large_table_start + idx64 * 8;
            if p + 8 > data.len() {
                return Err(format!("对象 {} 的 64 位偏移表项越界", oids[i]));
            }
            u64::from_be_bytes([
                data[p],
                data[p + 1],
                data[p + 2],
                data[p + 3],
                data[p + 4],
                data[p + 5],
                data[p + 6],
                data[p + 7],
            ])
        } else {
            raw as u64
        };
        entries.push(IdxEntry {
            oid: oids[i].clone(),
            crc32: crcs[i],
            offset,
        });
    }
    let trailer_start = data.len() - 40;
    let pack_checksum = hex::encode(&data[trailer_start..trailer_start + 20]);
    let idx_checksum = hex::encode(&data[trailer_start + 20..]);
    let checksum_ok = crate::gitobj::sha1_hex(&data[..trailer_start + 20]) == idx_checksum;
    Ok(IdxParse {
        fanout,
        entries,
        pack_checksum,
        idx_checksum,
        checksum_ok,
    })
}
