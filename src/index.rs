use crate::git::sha1_hex;

#[derive(Clone, Debug)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Clone, Debug)]
pub struct IndexInfo {
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: String,
    pub self_checksum_ok: bool,
    pub error: Option<String>,
}

pub fn parse_index(buf: &[u8]) -> IndexInfo {
    let mut err = None;
    let mut info = IndexInfo {
        fanout: Vec::new(),
        entries: Vec::new(),
        pack_checksum: String::new(),
        self_checksum_ok: false,
        error: None,
    };
    if buf.len() < 8 || &buf[0..4] != b"\xfftOc" {
        info.error = Some("缺少 index v2 魔数（仅支持 v2）".into());
        return info;
    }
    let version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    if version != 2 {
        info.error = Some(format!("不支持的 index 版本 {version}"));
        return info;
    }
    if buf.len() < 8 + 256 * 4 {
        info.error = Some("fanout 表被截断".into());
        return info;
    }
    let mut pos = 8usize;
    let mut fanout = Vec::with_capacity(256);
    for _ in 0..256 {
        fanout.push(u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()));
        pos += 4;
    }
    for w in fanout.windows(2) {
        if w[1] < w[0] {
            err = Some("fanout 表非单调递增".into());
        }
    }
    let count = *fanout.last().unwrap() as usize;
    let need = 8 + 256 * 4 + count * 20 + count * 4 + count * 4 + 40;
    if buf.len() < need {
        info.fanout = fanout;
        info.error = Some(format!("index 数据被截断: 需要 {need} 字节，实际 {} 字节", buf.len()));
        return info;
    }
    let mut oids = Vec::with_capacity(count);
    for _ in 0..count {
        oids.push(hex::encode(&buf[pos..pos + 20]));
        pos += 20;
    }
    let mut crcs = Vec::with_capacity(count);
    for _ in 0..count {
        crcs.push(u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap()));
        pos += 4;
    }
    let large_table_pos = 8 + 256 * 4 + count * 28 + count * 4;
    let mut offsets = Vec::with_capacity(count);
    for _ in 0..count {
        let raw = u32::from_be_bytes(buf[pos..pos + 4].try_into().unwrap());
        pos += 4;
        if raw & 0x8000_0000 != 0 {
            let li = (raw & 0x7fff_ffff) as usize;
            let p = large_table_pos + li * 8;
            if p + 8 > buf.len() - 40 {
                info.error = Some("64 位偏移表索引越界".into());
                return info;
            }
            offsets.push(u64::from_be_bytes(buf[p..p + 8].try_into().unwrap()));
        } else {
            offsets.push(raw as u64);
        }
    }
    info.pack_checksum = hex::encode(&buf[pos..pos + 20]);
    pos += 20;
    let declared_self = hex::encode(&buf[pos..pos + 20]);
    let actual_self = sha1_hex(&buf[..pos]);
    info.self_checksum_ok = declared_self == actual_self;
    if !info.self_checksum_ok && err.is_none() {
        err = Some(format!(
            "index 自校验失败: 声明 {declared_self} 实际 {actual_self}"
        ));
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        entries.push(IdxEntry {
            oid: oids[i].clone(),
            crc32: crcs[i],
            offset: offsets[i],
        });
    }
    info.fanout = fanout;
    info.entries = entries;
    info.error = err;
    info
}
