//! Git pack index 解析（v2 为主，兼容 v1），含 fanout 与校验。
use crate::gitobj;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct ParsedIdx {
    pub version: u32,
    pub fanout: Vec<u32>, // 256 项
    pub entries: Vec<IdxEntry>,
    pub pack_sha1: String,
    pub checksum_ok: bool,
    pub errors: Vec<String>,
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}
fn be64(b: &[u8], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[at..at + 8]);
    u64::from_be_bytes(v)
}

pub fn parse_idx(bytes: &[u8]) -> Result<ParsedIdx, String> {
    if bytes.len() >= 8 && &bytes[0..4] == b"\xfftOc" {
        parse_v2(bytes)
    } else {
        parse_v1(bytes)
    }
}

fn check_fanout(fanout: &[u32], errors: &mut Vec<String>) {
    for w in fanout.windows(2) {
        if w[1] < w[0] {
            errors.push("fanout 表非单调递增，索引可能损坏".into());
            break;
        }
    }
}

fn parse_v2(bytes: &[u8]) -> Result<ParsedIdx, String> {
    let version = be32(bytes, 4);
    if version != 2 {
        return Err(format!("不支持的 idx 版本 {version}"));
    }
    if bytes.len() < 8 + 256 * 4 + 40 {
        return Err("idx 文件太小".into());
    }
    let mut errors = Vec::new();
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        fanout.push(be32(bytes, 8 + i * 4));
    }
    check_fanout(&fanout, &mut errors);
    let n = fanout[255] as usize;
    let need = 8 + 256 * 4 + n * 20 + n * 4 + n * 4 + 40;
    if bytes.len() < need {
        return Err(format!("idx 截断: 需要至少 {need} 字节，实际 {}", bytes.len()));
    }
    let sha_base = 8 + 256 * 4;
    let crc_base = sha_base + n * 20;
    let off_base = crc_base + n * 4;
    let big_base = off_base + n * 4;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid = hex::encode(&bytes[sha_base + i * 20..sha_base + i * 20 + 20]);
        let crc32 = be32(bytes, crc_base + i * 4);
        let raw = be32(bytes, off_base + i * 4);
        let offset = if raw & 0x8000_0000 != 0 {
            let idx64 = (raw & 0x7fff_ffff) as usize;
            let at = big_base + idx64 * 8;
            if at + 8 > bytes.len() {
                errors.push(format!("oid {oid}: 64 位偏移表越界"));
                0
            } else {
                be64(bytes, at)
            }
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let pack_sha1 = hex::encode(&bytes[bytes.len() - 40..bytes.len() - 20]);
    let recorded = hex::encode(&bytes[bytes.len() - 20..]);
    let checksum_ok = gitobj::sha1_hex(&bytes[..bytes.len() - 20]) == recorded;
    if !checksum_ok {
        errors.push("idx 自身校验和不匹配".into());
    }
    Ok(ParsedIdx {
        version: 2,
        fanout,
        entries,
        pack_sha1,
        checksum_ok,
        errors,
    })
}

fn parse_v1(bytes: &[u8]) -> Result<ParsedIdx, String> {
    if bytes.len() < 256 * 4 + 40 {
        return Err("idx v1 文件太小".into());
    }
    let mut errors = vec!["idx 为 v1 格式（无 CRC 表）".to_string()];
    let mut fanout = Vec::with_capacity(256);
    for i in 0..256 {
        fanout.push(be32(bytes, i * 4));
    }
    check_fanout(&fanout, &mut errors);
    let n = fanout[255] as usize;
    let need = 256 * 4 + n * 24 + 40;
    if bytes.len() < need {
        return Err(format!("idx v1 截断: 需要 {need}，实际 {}", bytes.len()));
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let at = 256 * 4 + i * 24;
        let offset = be32(bytes, at) as u64;
        let oid = hex::encode(&bytes[at + 4..at + 24]);
        entries.push(IdxEntry { oid, crc32: 0, offset });
    }
    let pack_sha1 = hex::encode(&bytes[bytes.len() - 40..bytes.len() - 20]);
    Ok(ParsedIdx {
        version: 1,
        fanout,
        entries,
        pack_sha1,
        checksum_ok: true,
        errors,
    })
}
