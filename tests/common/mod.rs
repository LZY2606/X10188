//! 纯 Rust 的小型 pack / idx 构造器，供集成测试制造各类异常。
//! 不调用系统 git。

use packchain_microscope::delta::{
    encode_delta_varint, encode_ofs_distance, encode_pack_object_header,
};
use packchain_microscope::gitobj::wrap_object;
use packchain_microscope::oid::{ObjType, Oid};
use packchain_microscope::zlib::deflate;
use sha1::{Digest, Sha1};

pub fn type_code(ty: ObjType) -> u8 {
    match ty {
        ObjType::Commit => 1,
        ObjType::Tree => 2,
        ObjType::Blob => 3,
        ObjType::Tag => 4,
        ObjType::OfsDelta => 6,
        ObjType::RefDelta => 7,
    }
}

/// 一个待写入 pack 的逻辑条目。
#[derive(Clone)]
pub struct Entry {
    pub ty: ObjType,
    /// base 类型（delta 条目还原对象的最终类型）。
    pub final_type: ObjType,
    /// base 对象内容（full 条目）或 delta 目标内容（delta 条目）。
    pub content: Vec<u8>,
    /// delta base 条目索引。
    pub base: Option<usize>,
    /// ref-delta 时要写入的 base oid（None 则按内容真实计算）。
    pub ref_oid_override: Option<Oid>,
    /// 强制篡改头部声明的压缩负载大小。
    pub fake_size: Option<u64>,
    /// 若为 Some，则不使用真实压缩数据，而是直接写入该原始 zlib 负载
    /// （用于制造坏 CRC / 损坏 zlib）。
    pub raw_zlib_override: Option<Vec<u8>>,
}

impl Entry {
    pub fn full(ty: ObjType, content: impl Into<Vec<u8>>) -> Entry {
        let c = content.into();
        Entry {
            ty,
            final_type: ty,
            content: c,
            base: None,
            ref_oid_override: None,
            fake_size: None,
            raw_zlib_override: None,
        }
    }
    pub fn ofs(final_type: ObjType, base: usize, target: impl Into<Vec<u8>>) -> Entry {
        Entry {
            ty: ObjType::OfsDelta,
            final_type,
            content: target.into(),
            base: Some(base),
            ref_oid_override: None,
            fake_size: None,
            raw_zlib_override: None,
        }
    }
    pub fn refd(final_type: ObjType, base: usize, target: impl Into<Vec<u8>>) -> Entry {
        Entry {
            ty: ObjType::RefDelta,
            final_type,
            content: target.into(),
            base: Some(base),
            ref_oid_override: None,
            fake_size: None,
            raw_zlib_override: None,
        }
    }
}

pub struct BuiltPack {
    pub bytes: Vec<u8>,
    pub offsets: Vec<u64>,
    /// 每条目“完整条目字节”范围（与 index CRC 对应）。
    pub ranges: Vec<(u64, u64)>,
    pub count: u32,
    /// pack 内容（不含 trailer）的 SHA-1，即真正的 pack id。
    pub pack_sha: [u8; 20],
}

/// 全 insert 的 delta（合法、简单，用于还原测试）。
pub fn insert_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut d = encode_delta_varint(base.len() as u64);
    d.extend(encode_delta_varint(target.len() as u64));
    for chunk in target.chunks(127) {
        d.push(chunk.len() as u8);
        d.extend_from_slice(chunk);
    }
    d
}

/// 混合 COPY + INSERT 的 delta：target = base 整体 + 追加尾注。
pub fn copy_append_delta(base: &[u8], append: &[u8]) -> Vec<u8> {
    let total = base.len() + append.len();
    let mut d = encode_delta_varint(base.len() as u64);
    d.extend(encode_delta_varint(total as u64));
    // COPY base（按 <64KiB 分段，单段最大 0x10000）。
    let mut off = 0usize;
    while off < base.len() {
        let size = (base.len() - off).min(0x10000);
        emit_copy(&mut d, off, size);
        off += size;
    }
    for chunk in append.chunks(127) {
        d.push(chunk.len() as u8);
        d.extend_from_slice(chunk);
    }
    d
}

fn emit_copy(d: &mut Vec<u8>, off: usize, size: usize) {
    let mut op: u8 = 0x80;
    let mut ov = off;
    let mut sv = size;
    for i in 0..4 {
        if ov & 0xff != 0 {
            op |= 1 << i;
        }
        ov >>= 8;
    }
    for i in 0..3 {
        if sv & 0xff != 0 {
            op |= 1 << (4 + i);
        }
        sv >>= 8;
    }
    d.push(op);
    let mut ov = off;
    for i in 0..4 {
        if op & (1 << i) != 0 {
            d.push((ov & 0xff) as u8);
            ov >>= 8;
        }
    }
    let mut sv = size;
    for i in 0..3 {
        if op & (1 << (4 + i)) != 0 {
            d.push((sv & 0xff) as u8);
            sv >>= 8;
        }
    }
}

pub struct BuildOptions {
    /// 不追加正确 trailer（制造 pack SHA 不匹配 / 截断）。
    pub bad_trailer: bool,
    /// trailer 写入固定错误值。
    pub wrong_trailer: bool,
}

impl Default for BuildOptions {
    fn default() -> Self {
        BuildOptions {
            bad_trailer: false,
            wrong_trailer: false,
        }
    }
}

pub fn build_pack(entries: &[Entry]) -> BuiltPack {
    build_pack_opts(entries, &BuildOptions::default())
}

pub fn build_pack_opts(entries: &[Entry], opts: &BuildOptions) -> BuiltPack {
    let mut body: Vec<u8>::new();
    body.extend_from_slice(b"PACK");
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    let mut offsets = Vec::new();
    let mut ranges = Vec::new();
    // 每条目“逻辑还原内容 + 最终类型”，供后续 delta 引用。
    let mut logical: Vec<(ObjType, Vec<u8>)> = Vec::new();

    for e in entries {
        let offset = body.len() as u64;
        offsets.push(offset);
        let start = body.len();

        match e.ty {
            ObjType::OfsDelta | ObjType::RefDelta => {
                let bi = e.base.expect("delta 条目需要 base 索引");
                let (base_type, base_content) = logical[bi].clone();
                let delta = insert_delta(&base_content, &e.content);
                let declared = e.fake_size.unwrap_or(delta.len() as u64);
                body.extend(encode_pack_object_header(type_code(e.ty), declared));
                if e.ty == ObjType::OfsDelta {
                    let dist = offset - offsets[bi];
                    body.extend(encode_ofs_distance(dist));
                } else {
                    let oid = e
                        .ref_oid_override
                        .unwrap_or_else(|| Oid(packchain_microscope::gitobj::hash_object(
                            base_type,
                            &base_content,
                        )));
                    body.extend_from_slice(&oid.0);
                }
                match &e.raw_zlib_override {
                    Some(raw) => body.extend_from_slice(raw),
                    None => body.extend_from_slice(&deflate(&delta)),
                }
                logical.push((e.final_type, e.content.clone()));
            }
            other => {
                let canonical = wrap_object(other, &e.content);
                let declared = e.fake_size.unwrap_or(canonical.len() as u64);
                body.extend(encode_pack_object_header(type_code(other), declared));
                match &e.raw_zlib_override {
                    Some(raw) => body.extend_from_slice(raw),
                    None => body.extend_from_slice(&deflate(&canonical)),
                }
                logical.push((other, e.content.clone()));
            }
        }
        ranges.push((start as u64, body.len() as u64));
    }

    let mut h = Sha1::new();
    Digest::update(&mut h, &body);
    let pack_sha: [u8; 20] = h.finalize().into();
    if !opts.bad_trailer {
        if opts.wrong_trailer {
            body.extend_from_slice(&[0xeeu8; 20]);
        } else {
            body.extend_from_slice(&pack_sha);
        }
    }
    BuiltPack {
        bytes: body,
        offsets,
        ranges,
        count: entries.len() as u32,
        pack_sha,
    }
}

/// 由已构造 pack 生成配套 v2 index。`oid_at(i)` 给出第 i 条目的声称 oid。
pub fn build_index_v2(pack_sha: &[u8; 20], rows: &[(Oid, u64, u32)]) -> Vec<u8> {
    let n = rows.len();
    let mut sorted: Vec<(Oid, u64, u32)> = rows.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    out.extend_from_slice(b"\xfftOc");
    out.extend_from_slice(&2u32.to_be_bytes());

    let mut fanout = [0u32; 256];
    for (oid, _, _) in &sorted {
        fanout[oid.0[0] as usize] += 1;
    }
    let mut acc = 0u32;
    for v in fanout.iter_mut() {
        acc += *v;
        *v = acc;
    }
    for v in fanout {
        out.extend_from_slice(&v.to_be_bytes());
    }
    for (oid, _, _) in &sorted {
        out.extend_from_slice(&oid.0);
    }
    for (_, _, crc) in &sorted {
        out.extend_from_slice(&crc.to_be_bytes());
    }
    let mut big = Vec::new();
    for (_, off, _) in &sorted {
        if *off <= u32::MAX as u64 {
            out.extend_from_slice(&(*off as u32).to_be_bytes());
        } else {
            let idx = big.len() / 8;
            let word = 0x8000_0000u32 | idx as u32;
            out.extend_from_slice(&word.to_be_bytes());
            big.extend_from_slice(&off.to_be_bytes());
        }
    }
    out.extend_from_slice(&big);
    out.extend_from_slice(pack_sha);
    let mut h = Sha1::new();
    Digest::update(&mut h, &out);
    let idx_sha: [u8; 20] = h.finalize().into();
    out.extend_from_slice(&idx_sha);
    out
}
