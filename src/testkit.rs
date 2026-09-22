//! 测试用小型 pack / index / loose 对象构造器（纯 Rust，供测试使用，不调用系统 git）。

use crate::gitcore::{git_oid, parse_entry_header, parse_ofs_distance};
use sha1::{Digest, Sha1};

pub fn zlib(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

pub fn entry_header(obj_type: u8, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut byte = (obj_type << 4) | (size as u8 & 0x0f);
    let mut rest = size >> 4;
    loop {
        if rest != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if rest == 0 {
            break;
        }
        byte = (rest & 0x7f) as u8;
        rest >>= 7;
    }
    out
}

pub fn ofs_distance_enc(distance: u64) -> Vec<u8> {
    let mut bytes = vec![(distance & 0x7f) as u8];
    let mut rest = distance >> 7;
    while rest != 0 {
        rest -= 1;
        bytes.push(0x80 | ((rest & 0x7f) as u8));
        rest >>= 7;
    }
    bytes.reverse();
    bytes
}

pub fn size_varint(size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = size;
    loop {
        let mut byte = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if rest == 0 {
            break;
        }
    }
    out
}

pub struct PackBuilder {
    pub bytes: Vec<u8>,
    pub offsets: Vec<u64>,
}

impl PackBuilder {
    pub fn new() -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PACK");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 4]); // count filled later
        Self { bytes, offsets: Vec::new() }
    }

    fn push_entry(&mut self, entry: &[u8]) -> u64 {
        let offset = self.bytes.len() as u64;
        self.offsets.push(offset);
        self.bytes.extend_from_slice(entry);
        offset
    }

    pub fn add_full(&mut self, obj_type: u8, content: &[u8]) -> u64 {
        let mut e = entry_header(obj_type, content.len() as u64);
        e.extend_from_slice(&zlib(content));
        self.push_entry(&e)
    }

    pub fn add_ofs_delta(&mut self, base_offset: u64, delta: &[u8]) -> u64 {
        // 在写入前当前长度即新 entry 的 offset
        let new_offset = self.bytes.len() as u64;
        let distance = new_offset - base_offset;
        let mut e = entry_header(crate::gitcore::OBJ_OFS_DELTA, delta.len() as u64);
        e.extend_from_slice(&ofs_distance_enc(distance));
        e.extend_from_slice(&zlib(delta));
        self.push_entry(&e)
    }

    pub fn add_ref_delta(&mut self, base_oid: &[u8; 20], delta: &[u8]) -> u64 {
        let mut e = entry_header(crate::gitcore::OBJ_REF_DELTA, delta.len() as u64);
        e.extend_from_slice(base_oid);
        e.extend_from_slice(&zlib(delta));
        self.push_entry(&e)
    }

    /// 写入原始 entry 字节（用于构造畸形 entry）。
    pub fn add_raw(&mut self, entry: &[u8]) -> u64 {
        self.push_entry(entry)
    }

    pub fn finish(mut self) -> Vec<u8> {
        let count = self.offsets.len() as u32;
        self.bytes[8..12].copy_from_slice(&count.to_be_bytes());
        let digest = Sha1::digest(&self.bytes);
        self.bytes.extend_from_slice(&digest);
        self.bytes
    }

    /// 使用伪造 trailer，用于测试 checksum 不匹配。
    pub fn finish_bad_trailer(mut self) -> Vec<u8> {
        let count = self.offsets.len() as u32;
        self.bytes[8..12].copy_from_slice(&count.to_be_bytes());
        self.bytes.extend_from_slice(&[0xabu8; 20]);
        self.bytes
    }
}

impl Default for PackBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// 生成 "复制整个 base + 追加 extra" 的 delta。
pub fn delta_copy_plus(base: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&size_varint(base.len() as u64));
    d.extend_from_slice(&size_varint((base.len() + extra.len()) as u64));
    // copy offset=0,size=base.len()
    let size = base.len();
    let mut cmd = 0x80u8;
    let mut operands = Vec::new();
    // offset 始终为 0，不带 offset 字节
    if size & 0xff != 0 {
        cmd |= 0x10;
        operands.push((size & 0xff) as u8);
    }
    if size >> 8 != 0 {
        cmd |= 0x20;
        operands.push(((size >> 8) & 0xff) as u8);
    }
    if size >> 16 != 0 {
        cmd |= 0x40;
        operands.push(((size >> 16) & 0xff) as u8);
    }
    d.push(cmd);
    d.extend_from_slice(&operands);
    if !extra.is_empty() {
        assert!(extra.len() <= 127);
        d.push(extra.len() as u8);
        d.extend_from_slice(extra);
    }
    d
}

/// 构造 index v2。entries: (oid, crc32, offset)。
pub fn build_index(entries: &[([u8; 20], u32, u64)], pack_checksum: &[u8; 20], corrupt_crc_for: Option<&[u8; 20]>) -> Vec<u8> {
    let mut sorted: Vec<&([u8; 20], u32, u64)> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let n = sorted.len();
    let mut data = Vec::new();
    data.extend_from_slice(b"\xfftOc");
    data.extend_from_slice(&2u32.to_be_bytes());
    let mut fanout = [0u32; 256];
    for (oid, _, _) in &sorted {
        fanout[oid[0] as usize] += 1;
    }
    let mut acc = 0u32;
    for v in fanout.iter_mut() {
        acc += *v;
        *v = acc;
    }
    for i in 0..256 {
        data.extend_from_slice(&fanout[i].to_be_bytes());
    }
    for (oid, _, _) in &sorted {
        data.extend_from_slice(oid);
    }
    for (oid, crc, _) in &sorted {
        let c = if corrupt_crc_for == Some(oid) { crc ^ 0xffff_ffff } else { *crc };
        data.extend_from_slice(&c.to_be_bytes());
    }
    let use_large = sorted.iter().any(|(_, _, off)| *off > u32::MAX as u64);
    let large_base_pos = 8 + 1024 + 20 * n + 4 * n + 4 * n;
    let mut large_offsets = Vec::new();
    for (_, _, off) in &sorted {
        if use_large {
            let idx = large_offsets.len() as u32 | 0x8000_0000;
            data.extend_from_slice(&idx.to_be_bytes());
            large_offsets.push(*off);
        } else {
            data.extend_from_slice(&(*off as u32).to_be_bytes());
        }
    }
    for off in &large_offsets {
        data.extend_from_slice(&off.to_be_bytes());
    }
    let _ = large_base_pos;
    data.extend_from_slice(pack_checksum);
    let digest = Sha1::digest(&data);
    data.extend_from_slice(&digest);
    data
}

pub fn loose_file(obj_type: u8, content: &[u8]) -> Vec<u8> {
    let mut stored = Vec::new();
    stored.extend_from_slice(format!("{} {}\0", crate::gitcore::type_name(obj_type), content.len()).as_bytes());
    stored.extend_from_slice(content);
    zlib(&stored)
}

pub fn expected_oid(obj_type: u8, content: &[u8]) -> [u8; 20] {
    git_oid(obj_type, content)
}

/// 测试自检：确保编码的 entry header / ofs 距离能被解析器读回。
pub fn roundtrip_check() {
    for &(t, s) in &[(3u8, 0u64), (3, 15), (3, 16), (6, 70000), (1, 1 << 30)] {
        let h = entry_header(t, s);
        let (tt, ss, _) = parse_entry_header(&h, 0).unwrap();
        assert_eq!((tt, ss), (t, s));
    }
    for d in [1u64, 127, 128, 5000, 1 << 30] {
        let enc = ofs_distance_enc(d);
        let (dd, _) = parse_ofs_distance(&enc, 0).unwrap();
        assert_eq!(dd, d);
    }
}
