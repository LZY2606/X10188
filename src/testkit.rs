//! 自建小 pack / idx / loose 的构造工具,供测试与演示使用(不调用系统 git)。

use crate::gitobj::{crc32, hex_decode, sha1_hex, ObjType};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::Write;

pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::fast());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn varint7(mut n: u64) -> Vec<u8> {
    let mut groups = vec![(n & 0x7f) as u8];
    n >>= 7;
    while n > 0 {
        groups.push((n & 0x7f) as u8);
        n >>= 7;
    }
    for i in 0..groups.len() - 1 {
        groups[i] |= 0x80;
    }
    groups
}

fn pack_entry_header(typ: ObjType, size: u64) -> Vec<u8> {
    let mut groups = vec![((typ.code() << 4) | ((size & 0x0f) as u8))];
    let mut s = size >> 4;
    while s > 0 {
        groups.push((s & 0x7f) as u8);
        s >>= 7;
    }
    for i in 0..groups.len() - 1 {
        groups[i] |= 0x80;
    }
    groups
}

fn encode_ofs(mut n: u64) -> Vec<u8> {
    let mut buf = vec![(n & 0x7f) as u8];
    loop {
        n >>= 7;
        if n == 0 {
            break;
        }
        n -= 1;
        buf.push(((n & 0x7f) | 0x80) as u8);
    }
    buf.reverse();
    buf
}

/// 生成把 base 变成 result 的 delta:拷贝公共前缀,插入其余部分。
pub fn build_delta(base: &[u8], result: &[u8]) -> Vec<u8> {
    let mut d = varint7(base.len() as u64);
    d.extend(varint7(result.len() as u64));
    let mut i = 0usize;
    while i < base.len() && i < result.len() && base[i] == result[i] {
        i += 1;
    }
    // copy 指令(可能分块,单块最大 0x10000)
    let mut off = 0usize;
    let mut remain = i;
    while remain > 0 {
        let chunk = remain.min(0x10000);
        let mut cmd = 0x80u8;
        let mut extra = Vec::new();
        // offset 编码(此处总是从 0 开始连续,简化:记录 off)
        let o = off as u64;
        for b in 0..4 {
            let byte = ((o >> (8 * b)) & 0xff) as u8;
            if byte != 0 {
                cmd |= 1 << b;
            }
        }
        let sz = if chunk == 0x10000 { 0u64 } else { chunk as u64 };
        for b in 0..3 {
            let byte = ((sz >> (8 * b)) & 0xff) as u8;
            if byte != 0 {
                cmd |= 0x10 << b;
            }
        }
        d.push(cmd);
        for b in 0..4 {
            let byte = ((o >> (8 * b)) & 0xff) as u8;
            if byte != 0 {
                extra.push(byte);
            }
        }
        for b in 0..3 {
            let byte = ((sz >> (8 * b)) & 0xff) as u8;
            if byte != 0 {
                extra.push(byte);
            }
        }
        d.extend(extra);
        off += chunk;
        remain -= chunk;
    }
    // insert 剩余部分,每条最多 127 字节
    let mut j = i;
    while j < result.len() {
        let n = (result.len() - j).min(127);
        d.push(n as u8);
        d.extend_from_slice(&result[j..j + n]);
        j += n;
    }
    if result.is_empty() && i == 0 {
        // 空结果:不需要指令
    }
    d
}

pub struct PackBuilder {
    pub entries: Vec<Vec<u8>>, // 每个 entry 的完整字节(含 entry header)
    pub offsets: Vec<u64>,
    pub oids: Vec<Option<String>>, // 期望的 oid(由调用方填,用于写 idx)
}

impl PackBuilder {
    pub fn new() -> Self {
        PackBuilder {
            entries: Vec::new(),
            offsets: Vec::new(),
            oids: Vec::new(),
        }
    }
    fn push(&mut self, bytes: Vec<u8>, oid: Option<String>) -> u64 {
        let off = 12 + self.entries.iter().map(|e| e.len() as u64).sum::<u64>();
        self.offsets.push(off);
        self.entries.push(bytes);
        self.oids.push(oid);
        off
    }
    pub fn add_full(&mut self, typ: ObjType, content: &[u8]) -> u64 {
        let mut e = pack_entry_header(typ, content.len() as u64);
        e.extend(zlib_compress(content));
        let oid = crate::gitobj::object_id(typ.name(), content);
        self.push(e, Some(oid))
    }
    pub fn add_ofs_delta(&mut self, base_off: u64, delta: &[u8]) -> u64 {
        let cur_off = 12 + self.entries.iter().map(|e| e.len() as u64).sum::<u64>();
        assert!(base_off < cur_off, "base 必须在当前对象之前");
        let mut e = pack_entry_header(ObjType::OfsDelta, delta.len() as u64);
        e.extend(encode_ofs(cur_off - base_off));
        e.extend(zlib_compress(delta));
        self.push(e, None)
    }
    pub fn add_ref_delta(&mut self, base_oid: &str, delta: &[u8]) -> u64 {
        let mut e = pack_entry_header(ObjType::RefDelta, delta.len() as u64);
        e.extend(hex_decode(base_oid).expect("合法 oid"));
        e.extend(zlib_compress(delta));
        self.push(e, None)
    }
    /// 声明大小与实际 zlib 内容不符(伪造大小)
    pub fn add_full_with_fake_size(&mut self, typ: ObjType, content: &[u8], fake_size: u64) -> u64 {
        let mut e = pack_entry_header(typ, fake_size);
        e.extend(zlib_compress(content));
        self.push(e, None)
    }
    pub fn finish(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(b"PACK");
        out.extend(2u32.to_be_bytes());
        out.extend((self.entries.len() as u32).to_be_bytes());
        for e in &self.entries {
            out.extend(e);
        }
        let sum = sha1_hex(&out);
        out.extend(hex_decode(&sum).unwrap());
        out
    }
    /// 每个 entry 的 crc32(对 entry 原始字节)
    pub fn crcs(&self) -> Vec<u32> {
        self.entries.iter().map(|e| crc32(e)).collect()
    }
}

/// 写 index v2。rows: (oid, crc, offset),内部按 oid 排序。
pub fn build_idx(rows: &[(String, u32, u64)], pack_sha1: &str) -> Vec<u8> {
    let mut rows = rows.to_vec();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = Vec::new();
    out.extend([0xff, 0x74, 0x4f, 0x63]);
    out.extend(2u32.to_be_bytes());
    let mut fanout = [0u32; 256];
    for (oid, _, _) in &rows {
        let first = hex_decode(oid).unwrap()[0] as usize;
        fanout[first] += 1;
    }
    let mut acc = 0u32;
    for i in 0..256 {
        acc += fanout[i];
        out.extend(acc.to_be_bytes());
    }
    for (oid, _, _) in &rows {
        out.extend(hex_decode(oid).unwrap());
    }
    for (_, crc, _) in &rows {
        out.extend(crc.to_be_bytes());
    }
    for (_, _, off) in &rows {
        out.extend((*off as u32).to_be_bytes());
    }
    out.extend(hex_decode(pack_sha1).unwrap());
    let sum = sha1_hex(&out);
    out.extend(hex_decode(&sum).unwrap());
    out
}

pub fn build_loose(typ: &str, content: &[u8]) -> Vec<u8> {
    let mut raw = format!("{} {}\0", typ, content.len()).into_bytes();
    raw.extend_from_slice(content);
    zlib_compress(&raw)
}
