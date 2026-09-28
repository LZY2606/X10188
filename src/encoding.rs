//! Git 二进制原语：不调用系统 git，全部从零实现。

use crate::types::GitType;
use sha1::{Digest, Sha1};

/// 读取 pack entry header 的变长 size/type。
/// 返回 (type_code, size, header 字节数)。
pub fn read_pack_entry_header(buf: &[u8], off: usize) -> Option<(u8, u64, usize)> {
    let first = *buf.get(off)?;
    let type_code = (first >> 4) & 0b0000_0111;
    let mut size = (first & 0b0000_1111) as u64;
    let mut shift = 4;
    let mut pos = off + 1;
    let mut cont = first & 0b1000_0000 != 0;
    while cont {
        let b = *buf.get(pos)?;
        size |= ((b & 0x7f) as u64) << shift;
        shift += 7;
        pos += 1;
        cont = b & 0x80 != 0;
    }
    Some((type_code, size, pos - off))
}

/// 写 pack entry header（供测试造包）。
pub fn write_pack_entry_header(out: &mut Vec<u8>, type_code: u8, size: u64) {
    let mut first = (type_code << 4) | ((size as u8) & 0x0f);
    let mut rest = size >> 4;
    if rest != 0 {
        first |= 0x80;
    }
    out.push(first);
    while rest != 0 {
        let mut b = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
}

/// 读取 ofs-delta 的负距离编码。返回 (negative_offset, 字节数)。
pub fn read_ofs_delta(buf: &[u8], off: usize) -> Option<(u64, usize)> {
    let first = *buf.get(off)?;
    if first & 0x80 == 0 {
        return None;
    }
    let mut value = (first & 0x7f) as u64;
    let mut pos = off + 1;
    let mut b = first;
    while b & 0x80 != 0 {
        b = *buf.get(pos)?;
        value = value.checked_add(1)?;
        value = value.checked_shl(7)?;
        value |= (b & 0x7f) as u64;
        pos += 1;
    }
    Some((value, pos - off))
}

/// 写 ofs-delta 负距离编码（供测试造包）。
pub fn write_ofs_delta(out: &mut Vec<u8>, negative_offset: u64) {
    assert!(negative_offset > 0, "ofs-delta distance must be > 0");
    let mut chunks: Vec<u8> = Vec::new();
    let mut v = negative_offset;
    chunks.push((v & 0x7f) as u8);
    v >>= 7;
    while v > 0 {
        chunks.push((v & 0x7f) as u8);
        v >>= 7;
    }
    let n = chunks.len();
    for i in (0..n).rev() {
        let mut b = chunks[i];
        if i != 0 {
            b |= 0x80;
        }
        out.push(b);
    }
}

/// delta payload 开头的变长 size（base size / result size）。
pub fn read_delta_size(buf: &[u8], off: usize) -> Option<(u64, usize)> {
    let mut size = 0u64;
    let mut shift = 0u32;
    let mut pos = off;
    loop {
        let b = *buf.get(pos)?;
        size |= ((b & 0x7f) as u64) << shift;
        pos += 1;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    Some((size, pos - off))
}

pub fn write_delta_size(out: &mut Vec<u8>, mut size: u64) {
    loop {
        let mut b = (size & 0x7f) as u8;
        size >>= 7;
        if size != 0 {
            b |= 0x80;
        }
        out.push(b);
        if size == 0 {
            break;
        }
    }
}

/// 计算 Git 对象 id：sha1(`<type> <len>\0<content>`)。
pub fn git_object_id(kind: GitType, content: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(kind.header());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update([0u8]);
    h.update(content);
    h.finalize().into()
}

/// 计算整段字节的 sha1（pack/index trailer 校验）。
pub fn sha1_bytes(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

pub fn oid_hex(bytes: &[u8; 20]) -> String {
    hex::encode(bytes)
}

pub fn parse_oid_hex(s: &str) -> Option<[u8; 20]> {
    let v = hex::decode(s.trim()).ok()?;
    v.as_slice().try_into().ok()
}

/// CRC32（IEEE 802.3，与 zlib crc32 一致），用于 pack idx CRC 校验。
pub struct Crc32 {
    state: u32,
}

const CRC_TABLE: once_cell_style::LazyCrc = once_cell_style::LazyCrc::new();

mod once_cell_style {
    pub struct LazyCrc {
        table: [u32; 256],
    }
    impl LazyCrc {
        pub const fn new() -> Self {
            let mut table = [0u32; 256];
            let mut i = 0usize;
            while i < 256 {
                let mut c = i as u32;
                let mut j = 0;
                while j < 8 {
                    c = if c & 1 != 0 { 0xedb88320 ^ (c >> 1) } else { c >> 1 };
                    j += 1;
                }
                table[i] = c;
                i += 1;
            }
            LazyCrc { table }
        }
    }
    impl std::ops::Deref for LazyCrc {
        type Target = [u32; 256];
        fn deref(&self) -> &Self::Target {
            &self.table
        }
    }
}

impl Crc32 {
    pub fn new() -> Self {
        Crc32 { state: 0xffff_ffff }
    }
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            let idx = ((self.state ^ b as u32) & 0xff) as usize;
            self.state = (self.state >> 8) ^ CRC_TABLE[idx];
        }
    }
    pub fn finish(self) -> u32 {
        self.state ^ 0xffff_ffff
    }
    pub fn checksum(data: &[u8]) -> u32 {
        let mut c = Crc32::new();
        c.update(data);
        c.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ofs_roundtrip() {
        for d in [1u64, 2, 127, 128, 255, 256, 65535, 65536, 1 << 30] {
            let mut buf = Vec::new();
            write_ofs_delta(&mut buf, d);
            let (back, n) = read_ofs_delta(&buf, 0).unwrap();
            assert_eq!(back, d);
            assert_eq!(n, buf.len());
        }
    }

    #[test]
    fn header_roundtrip() {
        for (code, size) in [(3u8, 0u64), (6, 15), (7, 16), (1, 1 << 20)] {
            let mut buf = Vec::new();
            write_pack_entry_header(&mut buf, code, size);
            let (c, s, n) = read_pack_entry_header(&buf, 0).unwrap();
            assert_eq!((c, s, n), (code, size, buf.len()));
        }
    }

    #[test]
    fn crc_known_vector() {
        // "123456789" -> 0xcbf43926
        assert_eq!(Crc32::checksum(b"123456789"), 0xcbf4_3926);
    }
}
