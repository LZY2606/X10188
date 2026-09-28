//! PACK v2 解析：header、对象头、ofs-delta 距离、ref-delta 20 字节 base、
//! zlib 流边界、尾部 sha1 校验，以及“大小欺骗”检测。

use flate2::{Decompress, FlushDecompress, Status};

use crate::gitobj::{
    hex_encode, read_varint7, type_name, TYPE_OFS_DELTA, TYPE_REF_DELTA,
};

#[derive(Debug, Clone)]
pub struct PackEntry {
    pub offset: u64,
    pub type_code: u8,
    pub type_name: String,
    pub declared_size: u64,
    /// 对象头（类型/大小/base 信息）结束位置，即压缩数据起点。
    pub data_off: u64,
    pub hdr_len: u64,
    /// zlib 流实际消耗的压缩字节数；None 表示流未正常结束（截断/损坏）。
    pub data_len: Option<u64>,
    pub base_offset: Option<i64>,
    pub base_oid: Option<String>,
    /// 解压后的负载（普通对象是内容，delta 对象是 delta 程序）。
    pub inflated: Option<Vec<u8>>,
    pub parse_error: Option<String>,
    /// 解压出的字节数与头部声明大小不一致（大小欺骗）。
    pub size_spoof: bool,
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub declared_trailer: String,
    pub actual_trailer: String,
    pub trailer_ok: bool,
}

fn u32be(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

/// 从 `input[start..]` 解压一个 zlib 流，返回 (解压结果, 消耗字节数)。
///
/// `expected` 为对象头声明的解压大小：
/// - 流提前结束且 total_out < expected：声明偏大（解压一半发现大小欺骗/截断）；
/// - 实际解压超过 expected：声明偏小。
/// 无论哪种不一致都返回错误，由调用方隔离该对象。
pub fn inflate_stream(input: &[u8], start: usize, expected: u64) -> Result<(Vec<u8>, usize), String> {
    let mut dec = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 1 << 16];
    let slice = &input[start..];
    let mut in_pos = 0usize;

    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let status = dec
            .decompress(&slice[in_pos..], &mut chunk, FlushDecompress::None)
            .map_err(|e| format!("zlib 解压失败: {}", e))?;
        in_pos = dec.total_in() as usize;
        let produced = (dec.total_out() - before_out) as usize;
        out.extend_from_slice(&chunk[..produced]);

        if dec.total_out() > expected {
            return Err(format!(
                "大小欺骗：对象头声明 {} 字节，实际至少解压出 {} 字节",
                expected, dec.total_out()
            ));
        }
        match status {
            Status::StreamEnd => break,
            Status::Ok | Status::BufError => {
                if dec.total_in() == before_in && produced == 0 {
                    return Err("zlib 流异常终止（无输入无输出），对象可能截断".to_string());
                }
                if in_pos >= slice.len() && status != Status::StreamEnd {
                    return Err("zlib 流未结束即耗尽输入，pack 被截断".to_string());
                }
            }
        }
    }

    if dec.total_out() != expected {
        return Err(format!(
            "大小欺骗：对象头声明 {} 字节，zlib 实际解压 {} 字节",
            expected, dec.total_out()
        ));
    }
    Ok((out, dec.total_in() as usize))
}

fn read_ofs_distance(data: &[u8], mut pos: usize) -> Option<(u64, usize)> {
    let start = pos;
    let mut byte = data[pos];
    pos += 1;
    let mut dist = u64::from(byte & 0x7f);
    while byte & 0x80 != 0 {
        byte = *data.get(pos)?;
        pos += 1;
        dist = (dist.wrapping_add(1) << 7) | u64::from(byte & 0x7f);
    }
    Some((dist, pos - start))
}

pub fn parse_pack(data: &[u8]) -> Result<PackFile, String> {
    if data.len() < 12 {
        return Err("文件不足 12 字节，不是 pack".to_string());
    }
    if &data[0..4] != b"PACK" {
        return Err("缺少 PACK 魔数".to_string());
    }
    let version = u32be(data, 4);
    if version != 2 && version != 3 {
        return Err(format!("不支持的 pack 版本 {}", version));
    }
    let count = u32be(data, 8);
    let payload_end = data.len().saturating_sub(20);

    let mut entries = Vec::with_capacity(count as usize);
    let mut pos = 12usize;

    for index in 0..count {
        let offset = pos as u64;
        if pos >= payload_end {
            entries.push(bad_entry(
                offset,
                0,
                format!("第 {} 个对象头超出 pack 范围（count={} 可能伪造）", index, count),
            ));
            break;
        }
        let first = data[pos];
        pos += 1;
        let type_code = (first >> 4) & 0x07;
        let mut declared = u64::from(first & 0x0f);
        let mut shift = 4u32;
        let mut cont = first & 0x80;
        let mut hdr_ok = true;
        while cont != 0 {
            if pos >= payload_end {
                entries.push(bad_entry(
                    offset,
                    type_code,
                    "对象头大小变长整数越界".to_string(),
                ));
                hdr_ok = false;
                break;
            }
            let b = data[pos];
            pos += 1;
            declared |= u64::from(b & 0x7f) << shift;
            shift += 7;
            cont = b & 0x80;
        }
        if !hdr_ok {
            break;
        }

        let mut base_offset: Option<i64> = None;
        let mut base_oid: Option<String> = None;

        if type_code == TYPE_OFS_DELTA {
            match read_ofs_distance(data, pos) {
                Some((dist, n)) => {
                    pos += n;
                    if dist > offset {
                        entries.push(bad_entry(
                            offset,
                            type_code,
                            format!(
                                "ofs-delta 距离越界：distance={} 大于对象自身偏移 {}",
                                dist, offset
                            ),
                        ));
                        break;
                    }
                    base_offset = Some(offset as i64 - dist as i64);
                }
                None => {
                    entries.push(bad_entry(
                        offset,
                        type_code,
                        "ofs-delta 距离编码越界".to_string(),
                    ));
                    break;
                }
            }
        } else if type_code == TYPE_REF_DELTA {
            if pos + 20 > payload_end {
                entries.push(bad_entry(
                    offset,
                    type_code,
                    "ref-delta 20 字节 base oid 越界".to_string(),
                ));
                break;
            }
            base_oid = Some(hex_encode(&data[pos..pos + 20]));
            pos += 20;
        }

        let data_off = pos as u64;
        let hdr_len = data_off - offset;
        let entry = match inflate_stream(data, pos, declared) {
            Ok((inflated, compressed_len)) => {
                pos += compressed_len;
                PackEntry {
                    offset,
                    type_code,
                    type_name: type_name(type_code),
                    declared_size: declared,
                    data_off,
                    hdr_len,
                    data_len: Some(compressed_len as u64),
                    base_offset,
                    base_oid,
                    inflated: Some(inflated),
                    parse_error: None,
                    size_spoof: false,
                }
            }
            Err(msg) => PackEntry {
                offset,
                type_code,
                type_name: type_name(type_code),
                declared_size: declared,
                data_off,
                hdr_len,
                data_len: None,
                base_offset,
                base_oid,
                inflated: None,
                parse_error: Some(msg),
                size_spoof: msg.contains("大小欺骗"),
            },
        };
        entries.push(entry);
    }

    let (declared_trailer, actual_trailer, trailer_ok) = if data.len() >= 20 {
        let declared = hex_encode(&data[payload_end..payload_end + 20]);
        let actual = hex_encode(sha1_digest(&data[..payload_end]));
        let ok = declared == actual;
        (declared, actual, ok)
    } else {
        (String::new(), String::new(), false)
    };

    Ok(PackFile {
        version,
        count,
        entries,
        declared_trailer,
        actual_trailer,
        trailer_ok,
    })
}

fn bad_entry(offset: u64, type_code: u8, err: String) -> PackEntry {
    PackEntry {
        offset,
        type_code,
        type_name: type_name(type_code),
        declared_size: 0,
        data_off: offset,
        hdr_len: 0,
        data_len: None,
        base_offset: None,
        base_oid: None,
        inflated: None,
        parse_error: Some(err),
        size_spoof: false,
    }
}

fn sha1_digest(data: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(data);
    let out = h.finalize();
    let mut a = [0u8; 20];
    a.copy_from_slice(&out);
    a
}
