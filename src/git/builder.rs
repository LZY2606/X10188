use sha1::{Digest, Sha1};

use super::object::hash_object;
use super::types::GitType;
use super::varint::crc32;
use super::zlib::deflate_raw;

/// 自造小型 pack：不调用系统 git，全部手工拼装。
#[derive(Default)]
pub struct PackBuilder {
    entries: Vec<(u64, Vec<u8>)>, // (offset, 完整磁盘记录)
    meta: Vec<EntryMeta>,
}

#[derive(Clone)]
struct EntryMeta {
    oid: [u8; 20],
    offset: u64,
}

fn encode_header(kind: u8, size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut b = ((kind as u8) << 4) | ((size as u8) & 0x0f);
    let mut size = size >> 4;
    while size > 0 {
        b |= 0x80;
        out.push(b);
        b = (size as u8) & 0x7f;
        size >>= 7;
    }
    out.push(b);
    out
}

fn encode_ofs(distance: u64) -> Vec<u8> {
    let mut bytes = vec![(distance & 0x7f) as u8];
    let mut d = distance >> 7;
    while d > 0 {
        d -= 1;
        bytes.push(0x80 | ((d & 0x7f) as u8));
        d >>= 7;
    }
    bytes.reverse();
    bytes
}

impl PackBuilder {
    fn push_record(&mut self, record: Vec<u8>, oid: [u8; 20]) -> u64 {
        let offset = 12 + self.entries.iter().map(|(_, r)| r.len()).sum::<usize>();
        self.entries.push((offset as u64, record));
        self.meta.push(EntryMeta { oid, offset: offset as u64 });
        offset as u64
    }

    pub fn add_object(&mut self, kind: GitType, content: &[u8]) -> u64 {
        let oid = hash_object(kind, content);
        let bits = match kind {
            GitType::Commit => 1,
            GitType::Tree => 2,
            GitType::Blob => 3,
            GitType::Tag => 4,
        };
        let mut rec = encode_header(bits, content.len());
        rec.extend_from_slice(&deflate_raw(content));
        self.push_record(rec, oid)
    }

    /// 追加一条 ofs-delta。
    pub fn add_ofs_delta(
        &mut self,
        base_offset: u64,
        target_oid: [u8; 20],
        delta: &[u8],
    ) -> u64 {
        let next_offset =
            12 + self.entries.iter().map(|(_, r)| r.len()).sum::<usize>();
        let distance = next_offset as u64 - base_offset;
        let mut rec = encode_header(6, delta.len());
        rec.extend_from_slice(&encode_ofs(distance));
        rec.extend_from_slice(&deflate_raw(delta));
        self.push_record(rec, target_oid)
    }

    /// 追加一条 ref-delta。
    pub fn add_ref_delta(
        &mut self,
        base_oid: [u8; 20],
        target_oid: [u8; 20],
        delta: &[u8],
    ) -> u64 {
        let mut rec = encode_header(7, delta.len());
        rec.extend_from_slice(&base_oid);
        rec.extend_from_slice(&deflate_raw(delta));
        self.push_record(rec, target_oid)
    }

    pub fn entry_offsets(&self) -> Vec<u64> {
        self.meta.iter().map(|m| m.offset).collect()
    }

    pub fn oids(&self) -> Vec<[u8; 20]> {
        self.meta.iter().map(|m| m.oid).collect()
    }

    /// 构造与当前 entry 记录匹配的 v2 index（含正确 CRC）。
    pub fn build_index(&self) -> Vec<u8> {
        build_v2_index(
            &self
                .entries
                .iter()
                .zip(self.meta.iter())
                .map(|((_, rec), m)| (m.oid, m.offset, crc32(rec)))
                .collect::<Vec<_>>(),
            None,
        )
    }

    pub fn build_with_pack_sha(&self, pack_sha: [u8; 20]) -> Vec<u8> {
        self.build_index_with_pack_sha(pack_sha)
    }

    pub fn build_index_with_pack_sha(&self, pack_sha: [u8; 20]) -> Vec<u8> {
        build_v2_index(
            &self
                .entries
                .iter()
                .zip(self.meta.iter())
                .map(|((_, rec), m)| (m.oid, m.offset, crc32(rec)))
                .collect::<Vec<_>>(),
            Some(pack_sha),
        )
    }

    /// 允许指定每条 entry 的 CRC（测试可故意写错）。
    pub fn build_index_custom_crc(&self, crcs: &[u32]) -> Vec<u8> {
        let rows = self
            .entries
            .iter()
            .zip(self.meta.iter())
            .enumerate()
            .map(|(i, ((_, _), m))| (m.oid, m.offset, crcs[i]))
            .collect::<Vec<_>>();
        build_v2_index(&rows, None)
    }

    /// 原始记录（可被测试改写，如伪造声明大小）。
    pub fn raw_records(&self) -> &[(u64, Vec<u8>)] {
        &self.entries
    }
    pub fn raw_records_mut(&mut self) -> &mut [(u64, Vec<u8>)] {
        &mut self.entries
    }

    pub fn finish(mut self) -> Vec<u8> {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for (_, rec) in &self.entries {
            pack.extend_from_slice(rec);
        }
        let mut h = Sha1::new();
        h.update(&pack);
        pack.extend_from_slice(&h.finalize());
        let _ = &mut self;
        pack
    }
}

pub struct IndexRow {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc: u32,
}

/// 直接构造 v2 index，便于测试自行指定 oid/offset/crc。
pub fn build_v2_index(rows_in: &[([u8; 20], u64, u32)], pack_sha: Option<[u8; 20]>) -> Vec<u8> {
    let mut rows: Vec<IndexRow> = rows_in
        .iter()
        .map(|(oid, offset, crc)| IndexRow { oid: *oid, offset: *offset, crc: *crc })
        .collect();
    rows.sort_by(|a, b| a.oid.cmp(&b.oid));

    let mut out = Vec::new();
    out.extend_from_slice(&0xff744f63u32.to_be_bytes());
    out.extend_from_slice(&2u32.to_be_bytes());

    let mut fanout = [0u32; 256];
    for r in &rows {
        fanout[r.oid[0] as usize] += 1;
    }
    let mut acc = 0u32;
    for slot in fanout.iter_mut() {
        acc += *slot;
        *slot = acc;
    }
    for v in &fanout {
        out.extend_from_slice(&v.to_be_bytes());
    }
    for r in &rows {
        out.extend_from_slice(&r.oid);
    }
    for r in &rows {
        out.extend_from_slice(&r.crc.to_be_bytes());
    }
    for r in &rows {
        if r.offset < (1 << 31) {
            out.extend_from_slice(&(r.offset as u32).to_be_bytes());
        } else {
            unimplemented!("测试不需要 64 位偏移表");
        }
    }
    // pack 校验 sha（测试不配套时可传任意值）。
    let ps = pack_sha.unwrap_or([0xa5; 20]);
    out.extend_from_slice(&ps);
    let mut h = Sha1::new();
    h.update(&out);
    out.extend_from_slice(&h.finalize());
    out
}

/// 构造一条“把整个 base 替换为 literal”的 delta。
pub fn literal_delta(base: &[u8], new_content: &[u8]) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(encode_size(base.len() as u64));
    d.extend(encode_size(new_content.len() as u64));
    let mut rest = new_content;
    while !rest.is_empty() {
        let n = rest.len().min(127);
        d.push(n as u8);
        d.extend_from_slice(&rest[..n]);
        rest = &rest[n..];
    }
    d
}

/// 构造一条 copy base 再 append literal 的 delta（结果 = base + extra）。
pub fn copy_append_delta(base: &[u8], extra: &[u8]) -> Vec<u8> {
    let result_len = base.len() + extra.len();
    let mut d = encode_size(base.len() as u64);
    d.extend(encode_size(result_len as u64));
    d.extend(copy_full(base.len()));
    let mut rest = extra;
    while !rest.is_empty() {
        let n = rest.len().min(127);
        d.push(n as u8);
        d.extend_from_slice(&rest[..n]);
        rest = &rest[n..];
    }
    d
}

fn encode_size(mut size: u64) -> Vec<u8> {
    let mut out = Vec::new();
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
    out
}

fn copy_full(len: usize) -> Vec<u8> {
    // opcode 0x80，offset=0, size=len（若为 65536 则 size 字段省略）。
    let mut out = vec![0x80u8];
    if len != 0x10000 {
        let size = len as u32;
        for i in 0..3u32 {
            if size & (0xff << (8 * i)) != 0 {
                out[0] |= 1u8 << (4 + i);
                out.push(((size >> (8 * i)) & 0xff) as u8);
            }
        }
    }
    out
}
