//! pack index (v2) 解析：fanout、oid 表、CRC32、偏移表、尾部校验。

use crate::gitobj::OID_LEN;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; OID_LEN],
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct IdxScan {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    /// idx 内记录的 pack 内容 sha1
    pub pack_sha1: [u8; OID_LEN],
    pub self_ok: bool,
    pub errors: Vec<String>,
}

pub fn scan_idx(data: &[u8]) -> Result<IdxScan, String> {
    let mut errors = Vec::new();
    if data.len() < 8 + 256 * 4 + 2 * OID_LEN {
        return Err("idx 太小".into());
    }
    if &data[0..4] != b"\xfftOc" {
        return Err("缺少 idx v2 magic".into());
    }
    let version = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if version != 2 {
        return Err(format!("不支持的 idx 版本 {version}"));
    }
    let mut fanout = [0u32; 256];
    for (i, f) in fanout.iter_mut().enumerate() {
        let p = 8 + i * 4;
        *f = u32::from_be_bytes([data[p], data[p + 1], data[p + 2], data[p + 3]]);
    }
    for i in 1..256 {
        if fanout[i] < fanout[i - 1] {
            errors.push(format!("fanout[{i:#04x}] 非单调递增"));
            break;
        }
    }
    let n = fanout[255] as usize;
    let oid_tab = 8 + 256 * 4;
    let crc_tab = oid_tab + n * OID_LEN;
    let off_tab = crc_tab + n * 4;
    let big_tab = off_tab + n * 4;
    if data.len() < big_tab + 2 * OID_LEN {
        return Err(format!("idx 截断: 需要至少 {} 字节", big_tab + 2 * OID_LEN));
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let mut oid = [0u8; OID_LEN];
        oid.copy_from_slice(&data[oid_tab + i * OID_LEN..oid_tab + (i + 1) * OID_LEN]);
        let cp = crc_tab + i * 4;
        let crc32 = u32::from_be_bytes([data[cp], data[cp + 1], data[cp + 2], data[cp + 3]]);
        let op = off_tab + i * 4;
        let raw = u32::from_be_bytes([data[op], data[op + 1], data[op + 2], data[op + 3]]);
        let offset = if raw & 0x8000_0000 != 0 {
            let bi = (raw & 0x7fff_ffff) as usize;
            let bp = big_tab + bi * 8;
            if bp + 8 > data.len() - 2 * OID_LEN {
                errors.push(format!("条目 {i}: 64 位偏移表越界"));
                0
            } else {
                u64::from_be_bytes(data[bp..bp + 8].try_into().unwrap())
            }
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    let trailer_at = data.len() - 2 * OID_LEN;
    let mut pack_sha1 = [0u8; OID_LEN];
    pack_sha1.copy_from_slice(&data[trailer_at..trailer_at + OID_LEN]);
    let mut idx_sha = [0u8; OID_LEN];
    idx_sha.copy_from_slice(&data[trailer_at + OID_LEN..]);
    let digest = Sha1::digest(&data[..trailer_at + OID_LEN]);
    let self_ok = digest.as_slice() == idx_sha;
    Ok(IdxScan {
        fanout,
        entries,
        pack_sha1,
        self_ok,
        errors,
    })
}
