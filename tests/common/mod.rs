#![allow(dead_code)]

use flate2::{write::ZlibEncoder, Compression};
use pack_microscope::oid::Oid;
use pack_microscope::{git, types::ObjKind, Engine};
use sha1::{Digest, Sha1};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

pub fn engine(dir: &Path) -> Arc<Engine> {
    Arc::new(Engine::open(dir).unwrap())
}

pub fn oid_of(kind: ObjKind, content: &[u8]) -> Oid {
    git::git_object_id(kind, content)
}

pub fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn write_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v > 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

pub fn encode_obj_header(type_num: u8, size: u64) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = size;
    let mut first = (type_num << 4) | ((v & 0x0f) as u8);
    v >>= 4;
    if v > 0 {
        first |= 0x80;
    }
    out.push(first);
    while v > 0 {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v > 0 {
            b |= 0x80;
        }
        out.push(b);
    }
    out
}

pub fn encode_ofs_distance(distance: u64) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    let mut v = distance;
    let mut b = (v & 0x7f) as u8;
    v >>= 7;
    while v > 0 {
        out.push(b | 0x80);
        v -= 1;
        b = (v & 0x7f) as u8;
        v >>= 7;
    }
    out.push(b);
    out
}

pub fn encode_copy(offset: usize, size: usize, d: &mut Vec<u8>) {
    let mut opcode = 0x80u8;
    let mut extra = Vec::new();
    for i in 0..4u32 {
        let byte = ((offset >> (8 * i)) & 0xff) as u8;
        if byte != 0 {
            opcode |= 1 << i;
            extra.push(byte);
        }
    }
    for i in 0..3u32 {
        let byte = ((size >> (8 * i)) & 0xff) as u8;
        if byte != 0 {
            opcode |= 1 << (4 + i);
            extra.push(byte);
        }
    }
    d.push(opcode);
    d.extend(extra);
}

/// 生成 delta：复制与 target 相同的前缀，其余用 insert。
pub fn make_delta(base: &[u8], target: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    write_varint(base.len() as u64, &mut d);
    write_varint(target.len() as u64, &mut d);
    let common = base
        .iter()
        .zip(target.iter())
        .take_while(|(a, b)| a == b)
        .count();
    if common > 0 {
        encode_copy(0, common, &mut d);
    }
    let rest = &target[common..];
    let mut i = 0usize;
    while i < rest.len() {
        let n = std::cmp::min(127, rest.len() - i);
        d.push(n as u8);
        d.extend_from_slice(&rest[i..i + n]);
        i += n;
    }
    d
}

pub enum EntrySpec {
    Base { kind: u8, content: Vec<u8> },
    OfsDelta { distance: u64, delta: Vec<u8>, declared: u64 },
    RefDelta { base: Oid, delta: Vec<u8>, declared: u64 },
}

pub struct BuiltPack {
    pub bytes: Vec<u8>,
    pub offsets: Vec<u64>,
    pub checksum: Oid,
}

pub fn build_pack(entries: &[EntrySpec]) -> BuiltPack {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"PACK");
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    let mut blobs: Vec<Vec<u8>> = Vec::new();
    for spec in entries {
        let mut blob = Vec::new();
        match spec {
            EntrySpec::Base { kind, content } => {
                blob.extend(encode_obj_header(*kind, content.len() as u64));
                blob.extend(zlib(content));
            }
            EntrySpec::OfsDelta { distance, delta, declared } => {
                blob.extend(encode_obj_header(6, *declared));
                blob.extend(encode_ofs_distance(*distance));
                blob.extend(zlib(delta));
            }
            EntrySpec::RefDelta { base, delta, declared } => {
                blob.extend(encode_obj_header(7, *declared));
                blob.extend_from_slice(base.as_bytes());
                blob.extend(zlib(delta));
            }
        }
        blobs.push(blob);
    }

    let mut offsets = Vec::new();
    let mut cur = 12u64;
    for b in &blobs {
        offsets.push(cur);
        body.extend_from_slice(b);
        cur += b.len() as u64;
    }

    let mut h = Sha1::new();
    h.update(&body);
    let sum = h.finalize();
    let mut o = [0u8; 20];
    o.copy_from_slice(&sum);
    body.extend_from_slice(&sum);
    BuiltPack { bytes: body, offsets, checksum: Oid(o) }
}

/// 构造 idx v2。entries: (oid, offset, compressed bytes)。
pub fn build_idx_v2(entries: &[(Oid, u64, &[u8])], pack_checksum: Oid) -> Vec<u8> {
    let mut sorted: Vec<&(Oid, u64, &[u8])> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    out.extend_from_slice(b"\xfftOc");
    out.extend_from_slice(&2u32.to_be_bytes());

    let mut counts = vec![0u32; 256];
    for (oid, _, _) in &sorted {
        counts[oid.as_bytes()[0] as usize] += 1;
    }
    let mut cum = 0u32;
    for i in 0..256 {
        cum += counts[i];
        out.extend_from_slice(&cum.to_be_bytes());
    }
    for (oid, _, _) in &sorted {
        out.extend_from_slice(oid.as_bytes());
    }
    for (_, _, compressed) in &sorted {
        out.extend_from_slice(&crc32fast::hash(compressed).to_be_bytes());
    }
    for (_, off, _) in &sorted {
        out.extend_from_slice(&(*off as u32).to_be_bytes());
    }
    out.extend_from_slice(pack_checksum.as_bytes());

    let mut h = Sha1::new();
    h.update(&out);
    out.extend_from_slice(&h.finalize());
    out
}

/// 构造 idx v2，但可篡改某条 CRC。
pub fn build_idx_v2_bad_crc(
    entries: &[(Oid, u64, &[u8])],
    pack_checksum: Oid,
    corrupt_index: usize,
) -> Vec<u8> {
    let mut sorted: Vec<&(Oid, u64, &[u8])> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    let mut out = Vec::new();
    out.extend_from_slice(b"\xfftOc");
    out.extend_from_slice(&2u32.to_be_bytes());

    let mut counts = vec![0u32; 256];
    for (oid, _, _) in &sorted {
        counts[oid.as_bytes()[0] as usize] += 1;
    }
    let mut cum = 0u32;
    for i in 0..256 {
        cum += counts[i];
        out.extend_from_slice(&cum.to_be_bytes());
    }
    for (oid, _, _) in &sorted {
        out.extend_from_slice(oid.as_bytes());
    }
    let crc_start = out.len();
    for (i, (_, _, compressed)) in sorted.iter().enumerate() {
        let mut crc = crc32fast::hash(compressed);
        if i == corrupt_index {
            crc ^= 0xdead_beef;
        }
        out.extend_from_slice(&crc.to_be_bytes());
    }
    let _ = crc_start;
    for (_, off, _) in &sorted {
        out.extend_from_slice(&(*off as u32).to_be_bytes());
    }
    out.extend_from_slice(pack_checksum.as_bytes());

    let mut h = Sha1::new();
    h.update(&out);
    out.extend_from_slice(&h.finalize());
    out
}

pub fn loose_object(type_num: u8, content: &[u8]) -> (Vec<u8>, Oid) {
    let word = match type_num {
        1 => "commit",
        2 => "tree",
        4 => "tag",
        _ => "blob",
    };
    let kind = ObjKind::from_word(word.as_bytes()).unwrap();
    let oid = git::git_object_id(kind, content);
    let mut raw = Vec::new();
    raw.extend_from_slice(word.as_bytes());
    raw.push(b' ');
    raw.extend_from_slice(content.len().to_string().as_bytes());
    raw.push(0);
    raw.extend_from_slice(content);
    (zlib(&raw), oid)
}

/// 从已构建 pack 中提取某偏移对象的“压缩数据”（用于构造 idx CRC）。
pub fn compressed_of(pack: &[u8], offset: u64, next_offset: u64) -> Vec<u8> {
    // 需要跳过 header：重新用核心解析更稳妥；这里由测试用 parse 结果传入更简单，
    // 故提供一个按已知 data_start 的版本。
    let _ = (pack, offset, next_offset);
    Vec::new()
}
