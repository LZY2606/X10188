//! Git pack index（主要支持 v2）解析：fanout、oid/offset 表、条目 CRC、trailer。

use sha1::{Digest, Sha1};

use crate::crc::crc32;
use crate::oid::Oid;

/// 单个 index 条目。
#[derive(Clone, Debug)]
pub struct IndexEntry {
    pub oid: Oid,
    pub pack_offset: u64,
    pub crc32: u32,
    /// 该 CRC 与 pack 实际字节是否一致（配套后验证）。
    pub crc_matches_pack: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct IndexParsed {
    pub file_name: String,
    pub version: u32,
    /// fanout 表的 256 项原样保留。
    pub fanout: [u32; 256],
    pub entries: Vec<IndexEntry>,
    /// index 中记录的 pack SHA-1（pack trailer 应与之相等）。
    pub pack_sha: Oid,
    /// index 文件自身的 SHA-1 校验。
    pub index_sha: Oid,
    pub index_sha_ok: bool,
    pub error: Option<String>,
}

fn u32b(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn u64b(b: &[u8]) -> u64 {
    u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// 解析 v2 pack index。
pub fn parse_index(file_name: &str, bytes: &[u8]) -> IndexParsed {
    let mut ip = IndexParsed {
        file_name: file_name.to_string(),
        version: 0,
        fanout: [0u32; 256],
        entries: Vec::new(),
        pack_sha: Oid::ZERO,
        index_sha: Oid::ZERO,
        index_sha_ok: false,
        error: None,
    };
    macro_rules! fail {
        ($msg:expr) => {{
            ip.error = Some($msg.to_string());
            return ip;
        }};
    }
    if bytes.len() < 8 {
        fail!("index 短于 8 字节");
    }
    if &bytes[0..4] == b"\xfftOc" {
        ip.version = u32b(&bytes[4..8]);
    } else {
        ip.version = 1;
    }
    if ip.version != 2 {
        fail!(format!("仅支持 v2 index，检测到版本 {}", ip.version));
    }

    // fanout 表起点 8，256 项 ×4。
    if bytes.len() < 8 + 256 * 4 {
        fail!("index 装不下 fanout 表");
    }
    for i in 0..256 {
        ip.fanout[i] = u32b(&bytes[8 + i * 4..8 + (i + 1) * 4]);
    }
    // fanout 单调非减、第一项 <= ...、最后一项为总数。
    for i in 1..256 {
        if ip.fanout[i] < ip.fanout[i - 1] {
            fail!(format!("fanout[{i}] 小于 fanout[{}]（fanout 非单调）", i - 1));
        }
    }
    let n = ip.fanout[255] as usize;
    let mut p = 8 + 256 * 4;
    let oid_table = p;
    p += n * 20;
    let crc_table = p;
    p += n * 4;
    let off_table = p;
    p += n * 4;
    let large_table = p;
    let need_tail = large_table + 20 + 20;
    if bytes.len() < need_tail {
        fail!("index 装不下 oid/crc/offset 表与 trailer");
    }

    // oid 表必须按二进制顺序（fanout 隐含的前缀计数）校验。
    for i in 0..n {
        let o = Oid(bytes[oid_table + i * 20..oid_table + (i + 1) * 20]
            .try_into()
            .unwrap());
        if i + 1 < n {
            let next = Oid(bytes[oid_table + (i + 1) * 20..oid_table + (i + 2) * 20]
                .try_into()
                .unwrap());
            if o >= next {
                fail!(format!("oid 表在第 {i} 项未严格升序"));
            }
        }
        // fanout 校验：first-byte 前缀计数必须与表一致。
        let fb = o.0[0] as usize;
        let expected_count = ip.fanout[fb] as usize;
        if i >= expected_count {
            fail!(format!("fanout 与 oid 表在首字节 {} 处不一致", fb as u8));
        }
        let crc = u32b(&bytes[crc_table + i * 4..crc_table + (i + 1) * 4]);
        let off_word = u32b(&bytes[off_table + i * 4..off_table + (i + 1) * 4]);
        let offset = if off_word & 0x8000_0000 != 0 {
            let li = (off_word & 0x7fff_ffff) as usize;
            let start = large_table + li * 8;
            if start + 8 > bytes.len() - 40 {
                fail!(format!("条目 {i} 64 位大偏移越界"));
            }
            u64b(&bytes[start..start + 8])
        } else {
            off_word as u64
        };
        ip.entries.push(IndexEntry {
            oid: o,
            pack_offset: offset,
            crc32: crc,
            crc_matches_pack: None,
        });
    }

    ip.pack_sha = Oid(bytes[large_table..large_table + 20].try_into().unwrap());
    ip.index_sha = Oid(bytes[large_table + 20..large_table + 40].try_into().unwrap());
    let mut h = Sha1::new();
    Digest::update(&mut h, &bytes[..large_table + 20]);
    let computed: [u8; 20] = h.finalize().into();
    ip.index_sha_ok = computed == ip.index_sha.0;
    if !ip.index_sha_ok {
        ip.error = Some(format!(
            "index SHA-1 校验失败：计算值 {}，尾部 {}",
            Oid(computed).short(),
            ip.index_sha.short()
        ));
    }
    ip
}

/// 用已解析的 pack 字节验证 index 每个条目的 CRC32 与 offset 落点。
/// 返回错误描述列表（每个坏条目一项），空列表表示全部一致。
pub fn verify_index_against_pack(
    index: &mut IndexParsed,
    pack_bytes: &[u8],
    entry_ranges: &std::collections::HashMap<u64, (u64, u64)>,
) -> Vec<(Oid, String)> {
    let mut problems = Vec::new();
    for e in index.entries.iter_mut() {
        let range = entry_ranges.get(&e.pack_offset);
        match range {
            None => {
                e.crc_matches_pack = Some(false);
                problems.push((
                    e.oid,
                    format!("index offset {} 在 pack 中没有对应条目起点", e.pack_offset),
                ));
            }
            Some((s, end)) => {
                let actual = crc32(&pack_bytes[*s as usize..*end as usize]);
                let ok = actual == e.crc32;
                e.crc_matches_pack = Some(ok);
                if !ok {
                    problems.push((
                        e.oid,
                        format!(
                            "条目 CRC32 不匹配：index={:08x} pack={:08x}（offset {}）",
                            e.crc32, actual, e.pack_offset
                        ),
                    ));
                }
            }
        }
    }
    problems
}
