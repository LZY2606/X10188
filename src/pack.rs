use crate::gitobj::*;
use crate::inflate::inflate_prefix;

#[derive(Debug, Clone)]
pub struct PackEntryInfo {
    pub offset: u64,
    pub raw_type: u8,
    pub declared_size: u64,
    pub data_offset: u64,   // zlib 流起点 (zlib 边界)
    pub data_len: u64,      // zlib 压缩字节数
    pub inflated_size: i64, // 实际解压大小, -1 表示解压中途超过声明大小
    pub base_offset: Option<u64>, // ofs-delta: base 在 pack 内的绝对偏移
    pub base_oid: Option<String>, // ref-delta: base oid
    pub size_spoof: bool,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct PackInfo {
    pub version: u32,
    pub count: u32,
    pub trailer_ok: bool,
    pub entries: Vec<PackEntryInfo>,
}

fn bad_entry(offset: u64, msg: String) -> PackEntryInfo {
    PackEntryInfo {
        offset,
        raw_type: 0,
        declared_size: 0,
        data_offset: 0,
        data_len: 0,
        inflated_size: 0,
        base_offset: None,
        base_oid: None,
        size_spoof: false,
        error: Some(msg),
    }
}

pub fn parse_pack(data: &[u8]) -> Result<PackInfo, String> {
    if data.len() < 12 + 20 {
        return Err("pack 文件太短".into());
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".into());
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {version}"));
    }
    let count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let trailer_ok = sha1_hex(&data[..data.len() - 20]) == hex::encode(&data[data.len() - 20..]);
    let mut entries = Vec::new();
    let mut pos = 12usize;
    for _ in 0..count {
        let entry_off = pos;
        if pos >= data.len() - 20 {
            entries.push(bad_entry(entry_off as u64, "条目越过 pack 尾部校验和".into()));
            break;
        }
        match parse_one(data, pos) {
            Ok((info, next)) => {
                entries.push(info);
                pos = next;
            }
            Err(e) => {
                entries.push(bad_entry(entry_off as u64, e));
                break;
            }
        }
    }
    Ok(PackInfo { version, count, trailer_ok, entries })
}

fn parse_one(data: &[u8], off: usize) -> Result<(PackEntryInfo, usize), String> {
    let (raw_type, size, hlen) = parse_entry_header(data, off)?;
    let mut pos = off + hlen;
    let mut base_offset = None;
    let mut base_oid = None;
    match raw_type {
        6 => {
            let (dist, n) = parse_ofs_distance(data, pos)?;
            pos += n;
            if dist as usize > off {
                return Err(format!("ofs 距离越界: 距离 {} 超过当前偏移 {}", dist, off));
            }
            base_offset = Some(off as u64 - dist);
        }
        7 => {
            if pos + 20 > data.len() {
                return Err("ref-delta base oid 截断".into());
            }
            base_oid = Some(hex::encode(&data[pos..pos + 20]));
            pos += 20;
        }
        1..=4 => {}
        _ => return Err(format!("未知对象类型 {raw_type}")),
    }
    let data_offset = pos;
    // 解析阶段完整解压以确定 zlib 边界; 大小欺骗在此记录, 引擎阶段会再次以 cap 解压复现中途失败
    let (content, clen) = match inflate_prefix(&data[pos..], None) {
        Ok(v) => v,
        Err(e) => {
            let spoof = e.contains("大小欺骗");
            return Ok((
                PackEntryInfo {
                    offset: off as u64,
                    raw_type,
                    declared_size: size,
                    data_offset: data_offset as u64,
                    data_len: 0,
                    inflated_size: -1,
                    base_offset,
                    base_oid,
                    size_spoof: spoof,
                    error: Some(e),
                },
                data.len() - 20,
            ));
        }
    };
    pos += clen;
    let spoof = content.len() as u64 != size;
    Ok((
        PackEntryInfo {
            offset: off as u64,
            raw_type,
            declared_size: size,
            data_offset: data_offset as u64,
            data_len: clen as u64,
            inflated_size: content.len() as i64,
            base_offset,
            base_oid,
            size_spoof: spoof,
            error: None,
        },
        pos,
    ))
}
