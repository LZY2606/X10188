//! 测试与示例用的 Git pack / idx / loose 构造器，自行压缩与编码，不调用 git。

use crate::git::{apply_delta, crc32, git_object_id, hex, IDX_SIGNATURE, PACK_SIGNATURE};
use flate2::{write::ZlibEncoder, Compression};
use sha1::{Digest, Sha1};
use std::io::Write;

use crate::git::ObjectType;

pub fn zlib_encode(data: &[u8]) -> Vec<u8> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

pub fn loose_bytes(kind: ObjectType, content: &[u8]) -> Vec<u8> {
    let name = kind.type_name().unwrap();
    let mut raw = Vec::new();
    raw.extend_from_slice(name.as_bytes());
    raw.push(b' ');
    raw.extend_from_slice(content.len().to_string().as_bytes());
    raw.push(0);
    raw.extend_from_slice(content);
    zlib_encode(&raw)
}

pub fn loose_file(kind: ObjectType, content: &[u8]) -> (String, Vec<u8>) {
    let oid = git_object_id(kind, content);
    let hex_oid = hex(&oid);
    (format!("{}/{}", &hex_oid[..2], &hex_oid[2..]), loose_bytes(kind, content))
}

fn write_size_header(type_bits: u8, size: u64, out: &mut Vec<u8>) {
    let mut first = (type_bits & 0x07) << 4;
    first |= (size & 0x0f) as u8;
    let mut rest = size >> 4;
    if rest > 0 {
        first |= 0x80;
    }
    out.push(first);
    while rest > 0 {
        let mut b = (rest & 0x7f) as u8;
        rest >>= 7;
        if rest > 0 {
            b |= 0x80;
        }
        out.push(b);
    }
}

fn write_ofs_distance(mut distance: u64, out: &mut Vec<u8>) {
    let mut bytes = vec![(distance & 0x7f) as u8];
    distance >>= 7;
    while distance > 0 {
        bytes.push((distance & 0x7f) as u8);
        distance >>= 7;
    }
    bytes.reverse();
    let last = bytes.len() - 1;
    for b in bytes.iter_mut().take(last) {
        *b |= 0x80;
    }
    out.extend_from_slice(&bytes);
}

fn write_delta_size(mut size: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (size & 0x7f) as u8;
        size >>= 7;
        if size > 0 {
            b |= 0x80;
        }
        out.push(b);
        if size == 0 {
            break;
        }
    }
}

#[derive(Debug, Clone)]
pub enum PackObject {
    Base {
        kind: ObjectType,
        content: Vec<u8>,
    },
    OfsDelta {
        base_index: usize,
        delta: Vec<u8>,
    },
    /// base_oid 写入 pack；base_kind/base_content 仅用于构造器推导最终对象。
    RefDelta {
        base_oid: [u8; 20],
        base_kind: ObjectType,
        base_content: Vec<u8>,
        delta: Vec<u8>,
    },
}

pub struct BuiltPack {
    pub data: Vec<u8>,
    pub offsets: Vec<u64>,
    /// 每个对象还原后的 (type, content)。
    pub finals: Vec<(ObjectType, Vec<u8>)>,
}

fn resolve_final(objects: &[PackObject], i: usize) -> (ObjectType, Vec<u8>) {
    match &objects[i] {
        PackObject::Base { kind, content } => (*kind, content.clone()),
        PackObject::OfsDelta { base_index, delta } => {
            let (kind, base_content) = resolve_final(objects, *base_index);
            let out = apply_delta(&base_content, delta).unwrap();
            (kind, out.data)
        }
        PackObject::RefDelta {
            base_kind,
            base_content,
            delta,
            ..
        } => {
            let out = apply_delta(base_content, delta).unwrap();
            (*base_kind, out.data)
        }
    }
}

/// 构造 pack。`size_lies`：(对象下标, 伪造 header size)。
pub fn build_pack(objects: &[PackObject], size_lies: &[(usize, u64)]) -> BuiltPack {
    let mut pack = Vec::new();
    pack.extend_from_slice(&PACK_SIGNATURE);
    pack.extend_from_slice(&2u32.to_be_bytes());
    pack.extend_from_slice(&(objects.len() as u32).to_be_bytes());
    let mut offsets = Vec::new();
    for (i, obj) in objects.iter().enumerate() {
        offsets.push(pack.len() as u64);
        let declared_payload = match obj {
            PackObject::Base { content, .. } => content.len() as u64,
            PackObject::OfsDelta { delta, .. } | PackObject::RefDelta { delta, .. } => {
                delta.len() as u64
            }
        };
        let lie = size_lies
            .iter()
            .find(|(idx, _)| *idx == i)
            .map(|(_, s)| *s)
            .unwrap_or(declared_payload);
        match obj {
            PackObject::Base { kind, .. } => write_size_header(*kind as u8, lie, &mut pack),
            PackObject::OfsDelta { base_index, .. } => {
                write_size_header(6, lie, &mut pack);
                let base_offset = offsets[*base_index];
                write_ofs_distance(pack.len() as u64 - base_offset, &mut pack);
            }
            PackObject::RefDelta { base_oid, .. } => {
                write_size_header(7, lie, &mut pack);
                pack.extend_from_slice(base_oid);
            }
        }
        let payload = match obj {
            PackObject::Base { content, .. } => zlib_encode(content),
            PackObject::OfsDelta { delta, .. } | PackObject::RefDelta { delta, .. } => {
                zlib_encode(delta)
            }
        };
        pack.extend_from_slice(&payload);
    }
    let mut hasher = Sha1::new();
    hasher.update(&pack);
    pack.extend_from_slice(&hasher.finalize());
    let finals = (0..objects.len()).map(|i| resolve_final(objects, i)).collect();
    BuiltPack {
        data: pack,
        offsets,
        finals,
    }
}

#[derive(Debug, Clone, Default)]
pub struct IdxCorruption {
    pub corrupt_crc_index: Option<usize>,
    pub corrupt_pack_checksum: bool,
    pub corrupt_idx_checksum: bool,
}

pub fn build_idx(
    pack: &[u8],
    offsets: &[u64],
    finals: &[(ObjectType, Vec<u8>)],
    corruption: &IdxCorruption,
) -> Vec<u8> {
    let count = offsets.len();
    let mut entries: Vec<([u8; 20], u32, u64)> = Vec::with_capacity(count);
    for i in 0..count {
        let oid = git_object_id(finals[i].0, &finals[i].1);
        let start = offsets[i] as usize;
        let end = if i + 1 < count {
            offsets[i + 1] as usize
        } else {
            pack.len() - 20
        };
        let mut crc = crc32(&pack[start..end]);
        if corruption.corrupt_crc_index == Some(i) {
            crc ^= 0xffff_ffff;
        }
        entries.push((oid, crc, offsets[i]));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut idx = Vec::new();
    idx.extend_from_slice(&IDX_SIGNATURE);
    idx.extend_from_slice(&2u32.to_be_bytes());
    let mut fanout = [0u32; 256];
    for (oid, _, _) in &entries {
        fanout[oid[0] as usize] += 1;
    }
    let mut cumulative = 0u32;
    for bucket in fanout.iter_mut() {
        cumulative += *bucket;
        *bucket = cumulative;
    }
    for v in fanout {
        idx.extend_from_slice(&v.to_be_bytes());
    }
    for (oid, _, _) in &entries {
        idx.extend_from_slice(oid);
    }
    for (_, crc, _) in &entries {
        idx.extend_from_slice(&crc.to_be_bytes());
    }
    for (_, _, offset) in &entries {
        idx.extend_from_slice(&(*offset as u32).to_be_bytes());
    }
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&pack[pack.len() - 20..]);
    if corruption.corrupt_pack_checksum {
        pack_checksum[0] ^= 0xff;
    }
    idx.extend_from_slice(&pack_checksum);
    let mut hasher = Sha1::new();
    hasher.update(&idx);
    let mut idx_checksum: [u8; 20] = hasher.finalize().into();
    if corruption.corrupt_idx_checksum {
        idx_checksum[0] ^= 0xff;
    }
    idx.extend_from_slice(&idx_checksum);
    idx
}

/// copy 全量 base，再 insert extra。
pub fn delta_append(base: &[u8], extra: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    write_delta_size(base.len() as u64, &mut d);
    write_delta_size((base.len() + extra.len()) as u64, &mut d);
    encode_copy(0, base.len() as u64, &mut d);
    let mut left = extra.len();
    let mut pos = 0;
    while left > 0 {
        let n = left.min(127);
        d.push(n as u8);
        d.extend_from_slice(&extra[pos..pos + n]);
        pos += n;
        left -= n;
    }
    d
}

fn encode_copy(offset: u64, size: u64, out: &mut Vec<u8>) {
    let mut opcode: u8 = 0x80;
    let mut off_bytes = [0u8; 4];
    let mut off_count = 0;
    let mut v = offset;
    while v > 0 {
        off_bytes[off_count] = (v & 0xff) as u8;
        off_count += 1;
        v >>= 8;
    }
    let mut size_bytes = [0u8; 3];
    let mut size_count = 0;
    let mut sv = size;
    while sv > 0 {
        size_bytes[size_count] = (sv & 0xff) as u8;
        size_count += 1;
        sv >>= 8;
    }
    for i in 0..off_count {
        opcode |= 1 << i;
    }
    for i in 0..size_count {
        opcode |= 1 << (4 + i);
    }
    out.push(opcode);
    out.extend_from_slice(&off_bytes[..off_count]);
    out.extend_from_slice(&size_bytes[..size_count]);
}

/// insert-only delta，结果与 base 内容无关（base_size=0）。
pub fn delta_insert(result: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    write_delta_size(0, &mut d);
    write_delta_size(result.len() as u64, &mut d);
    let mut left = result.len();
    let mut pos = 0;
    while left > 0 {
        let n = left.min(127);
        d.push(n as u8);
        d.extend_from_slice(&result[pos..pos + n]);
        pos += n;
        left -= n;
    }
    d
}
