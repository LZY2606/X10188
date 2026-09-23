use sha1::{Digest, Sha1};

use super::types::{Evidence, GitType, InflateStatus, PackKind};
use super::varint::{crc32, read_ofs_distance, read_pack_header_size, u32be};
use super::zlib::inflate_entry;

#[derive(Debug, Clone)]
pub struct PackEntry {
    /// 该 entry 在 pack 中的起始偏移（类型字节所在处）。
    pub offset: u64,
    /// 压缩数据（含 entry 头）在 pack 中的字节范围。
    pub header_start: u64,
    pub data_end: u64,
    pub kind: PackKind,
    pub declared_size: u64,
    /// ofs-delta：基对象绝对偏移；ref-delta：基对象 oid。
    pub base_offset: Option<u64>,
    pub base_oid: Option<[u8; 20]>,
    /// entry 头结束、zlib 流开始的位置。
    pub zlib_start: u64,
    /// 解压后的 delta 指令数据或最终对象数据。
    pub inflated: Vec<u8>,
    pub inflate_status: InflateStatus,
    /// 覆盖“整个 entry 记录（头+压缩流）”的 CRC32。
    pub record_crc: u32,
}

impl PackEntry {
    pub fn final_type(&self) -> Option<GitType> {
        GitType::from_pack(self.kind)
    }
}

#[derive(Debug, Clone)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    /// pack 级证据（header/尾部 sha 等）。
    pub evidence: Vec<Evidence>,
    pub trailer_stored: Option<[u8; 20]>,
    pub trailer_computed: Option<[u8; 20]>,
}

pub fn parse_pack(data: &[u8]) -> Result<PackFile, Vec<Evidence>> {
    let mut evidence = Vec::new();
    if data.len() < 12 + 20 || &data[0..4] != b"PACK" {
        return Err(vec![Evidence::new("pack_bad_magic", "缺少 PACK 魔数")]);
    }
    let version = u32be(data, 4).unwrap();
    let count = u32be(data, 8).unwrap();
    if version != 2 {
        evidence.push(Evidence::new("pack_bad_version", format!("不支持的 pack 版本 {}", version)));
    }

    // 计算 pack 校验 sha（不含最后 20 字节）。
    let mut h = Sha1::new();
    h.update(&data[..data.len() - 20]);
    let mut trailer_computed = [0u8; 20];
    trailer_computed.copy_from_slice(&h.finalize());
    let mut trailer_stored = [0u8; 20];
    trailer_stored.copy_from_slice(&data[data.len() - 20..]);
    if trailer_computed != trailer_stored {
        evidence.push(Evidence::new(
            "pack_trailer_sha_mismatch",
            "pack 尾部 SHA-1 与文件内容不一致（文件可能被截断/篡改）",
        ));
    }

    let mut entries = Vec::new();
    let mut pos = 12usize;
    let parse_end = data.len() - 20;

    for index in 0..count {
        let entry_offset = pos;
        if entry_offset >= parse_end {
            evidence.push(Evidence::new(
                "pack_truncated",
                format!("第 {} 个对象越界（头部缺失）", index),
            ));
            break;
        }
        let header_start = pos;
        let (bits, declared_size) = match read_pack_header_size(data, &mut pos) {
            Some(v) => v,
            None => {
                evidence.push(Evidence::new(
                    "pack_truncated",
                    format!("偏移 {} 处对象头不完整", entry_offset),
                ));
                break;
            }
        };
        let kind = match PackKind::from_bits(bits) {
            Some(k) => k,
            None => {
                evidence.push(Evidence::new(
                    "pack_bad_type",
                    format!("偏移 {} 处出现未知对象类型 {}", entry_offset, bits),
                ));
                break;
            }
        };

        let mut base_offset = None;
        let mut base_oid = None;
        match kind {
            PackKind::OfsDelta => {
                let anchor = pos;
                let dist = match read_ofs_distance(data, &mut pos) {
                    Some(d) => d,
                    None => {
                        evidence.push(Evidence::new(
                            "ofs_truncated",
                            format!("偏移 {} 处 ofs-delta 距离不完整", entry_offset),
                        ));
                        break;
                    }
                };
                match (entry_offset as u64).checked_sub(dist) {
                    Some(t) if (t as usize) >= 12 && (t as usize) < entry_offset => {
                        base_offset = Some(t);
                    }
                    _ => {
                        evidence.push(Evidence::new(
                            "ofs_out_of_range",
                            format!(
                                "偏移 {} 处 ofs-delta 距离 {} 指向越界/前向位置",
                                entry_offset, dist
                            ),
                        ));
                    }
                }
                let _ = anchor;
            }
            PackKind::RefDelta => {
                if pos + 20 > data.len() {
                    evidence.push(Evidence::new(
                        "ref_truncated",
                        format!("偏移 {} 处 ref-delta 基 oid 不完整", entry_offset),
                    ));
                    break;
                }
                let mut oid = [0u8; 20];
                oid.copy_from_slice(&data[pos..pos + 20]);
                pos += 20;
                base_oid = Some(oid);
            }
            _ => {}
        }

        let zlib_start = pos;
        let inf = inflate_entry(data, pos, declared_size);
        let consumed = inf.input_consumed;
        let data_end = pos + consumed.max(1);

        if inf.status == InflateStatus::Ok && inf.data.len() as u64 != declared_size {
            evidence.push(Evidence::new(
                "size_spoof",
                format!(
                    "偏移 {} 处声明大小 {} 与解压大小 {} 不一致",
                    entry_offset,
                    declared_size,
                    inf.data.len()
                ),
            ));
        }
        if inf.status != InflateStatus::Ok {
            let code = match inf.status {
                InflateStatus::SizeSpoof => "size_spoof",
                InflateStatus::Truncated => "zlib_truncated",
                InflateStatus::ZlibError => "zlib_error",
                InflateStatus::Ok => unreachable!(),
            };
            evidence.push(Evidence::new(
                code,
                format!("偏移 {} 处 zlib 解压状态 {:?}", entry_offset, inf.status),
            ));
        }

        let record_crc = crc32(&data[header_start..data_end.min(parse_end)]);
        entries.push(PackEntry {
            offset: entry_offset as u64,
            header_start: header_start as u64,
            data_end: data_end as u64,
            kind,
            declared_size,
            base_offset,
            base_oid,
            zlib_start: zlib_start as u64,
            inflated: inf.data,
            inflate_status: inf.status,
            record_crc,
        });

        pos = data_end;
        if pos > parse_end {
            evidence.push(Evidence::new(
                "pack_overrun",
                format!("偏移 {} 处对象数据越过 pack 边界", entry_offset),
            ));
            break;
        }
    }

    if entries.len() as u32 != count {
        evidence.push(Evidence::new(
            "pack_count_mismatch",
            format!("头部声明 {} 个对象，实际解析出 {} 个", count, entries.len()),
        ));
    }

    if !evidence.is_empty() && entries.is_empty() {
        return Err(evidence);
    }
    Ok(PackFile {
        version,
        count,
        entries,
        evidence,
        trailer_stored: Some(trailer_stored),
        trailer_computed: Some(trailer_computed),
    })
}
