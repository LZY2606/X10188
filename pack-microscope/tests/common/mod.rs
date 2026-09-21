use flate2::{write::ZlibEncoder, Compression};
use pack_microscope::git::git_object_id;
use sha1::{Digest, Sha1};
use std::io::Write;

pub fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn object(type_name: &str, content: &[u8]) -> (Vec<u8>, [u8; 20]) {
    let mut full = Vec::new();
    full.extend_from_slice(type_name.as_bytes());
    full.push(b' ');
    full.extend_from_slice(content.len().to_string().as_bytes());
    full.push(0);
    full.extend_from_slice(content);
    let mut h = Sha1::new();
    h.update(&full);
    let _ = h;
    let oid = git_object_id(type_name, content);
    (full, oid)
}

pub fn encode_entry_header(type_code: u8, size: usize) -> Vec<u8> {
    let mut v = Vec::new();
    let mut s = size;
    let mut first = (type_code & 7) << 4;
    first |= (s & 0x0f) as u8;
    s >>= 4;
    if s > 0 {
        first |= 0x80;
    }
    v.push(first);
    while s > 0 {
        let mut b = (s & 0x7f) as u8;
        s >>= 7;
        if s > 0 {
            b |= 0x80;
        }
        v.push(b);
    }
    v
}

pub fn encode_ofs_distance(dist: u64) -> Vec<u8> {
    let mut v = Vec::new();
    let mut d = dist;
    let mut bytes = vec![(d & 0x7f) as u8];
    d >>= 7;
    while d > 0 {
        d -= 1;
        bytes.push(((d & 0x7f) as u8) | 0x80);
        d >>= 7;
    }
    bytes.reverse();
    v.extend_from_slice(&bytes);
    v
}

pub struct PackBuilder {
    entries: Vec<Vec<u8>>,
}

impl PackBuilder {
    pub fn new() -> Self {
        PackBuilder {
            entries: Vec::new(),
        }
    }

    pub fn add_blob(&mut self, content: &[u8]) -> ([u8; 20], usize) {
        let oid = git_object_id("blob", content);
        let mut e = encode_entry_header(3, content.len());
        e.extend_from_slice(&zlib(content));
        let off = self.current_offset();
        self.entries.push(e);
        (oid, off)
    }

    pub fn add_typed(&mut self, type_code: u8, declared_size: usize, payload: &[u8]) -> usize {
        let mut e = encode_entry_header(type_code, declared_size);
        e.extend_from_slice(&zlib(payload));
        let off = self.current_offset();
        self.entries.push(e);
        off
    }

    pub fn add_ofs_delta(&mut self, base_offset: usize, base: &[u8], target: &[u8]) -> usize {
        let my_off = self.current_offset();
        let dist = (my_off - base_offset) as u64;
        let delta = pack_microscope::delta::make_delta(base, target);
        let mut e = encode_entry_header(6, delta.len());
        e.extend_from_slice(&encode_ofs_distance(dist));
        e.extend_from_slice(&zlib(&delta));
        let off = self.current_offset();
        self.entries.push(e);
        off
    }

    pub fn add_ofs_delta_raw(&mut self, base_offset: usize, delta_payload: &[u8]) -> usize {
        let my_off = self.current_offset();
        let dist = (my_off - base_offset) as u64;
        let mut e = encode_entry_header(6, delta_payload.len());
        e.extend_from_slice(&encode_ofs_distance(dist));
        e.extend_from_slice(&zlib(delta_payload));
        let off = self.current_offset();
        self.entries.push(e);
        off
    }

    pub fn add_ref_delta(&mut self, base_oid: &[u8; 20], base: &[u8], target: &[u8]) -> usize {
        let delta = pack_microscope::delta::make_delta(&base, target);
        let mut e = encode_entry_header(7, delta.len());
        e.extend_from_slice(base_oid);
        e.extend_from_slice(&zlib(&delta));
        let off = self.current_offset();
        self.entries.push(e);
        off
    }

    pub fn add_ref_delta_raw(&mut self, base_oid: &[u8; 20], delta_payload: &[u8]) -> usize {
        let mut e = encode_entry_header(7, delta_payload.len());
        e.extend_from_slice(base_oid);
        e.extend_from_slice(&zlib(delta_payload));
        let off = self.current_offset();
        self.entries.push(e);
        off
    }

    pub fn current_offset(&self) -> usize {
        12 + self.entries.iter().map(|e| e.len()).sum::<usize>()
    }

    pub fn build(self) -> (Vec<u8>, Vec<usize>) {
        let count = self.entries.len() as u32;
        self.build_with_count(count)
    }

    pub fn build_with_count(mut self, count: u32) -> (Vec<u8>, Vec<usize>) {
        let offsets: Vec<usize> = {
            let mut off = 12usize;
            let mut v = Vec::new();
            for e in &self.entries {
                v.push(off);
                off += e.len();
            }
            v
        };
        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        for e in self.entries.drain(..) {
            out.extend_from_slice(&e);
        }
        let mut h = Sha1::new();
        h.update(&out);
        let sha: [u8; 20] = h.finalize().into();
        out.extend_from_slice(&sha);
        (out, offsets)
    }

    pub fn corrupt_pack_checksum(mut self) -> Vec<u8> {
        let (mut bytes, _) = self.build();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        bytes
    }
}

pub struct IdxSpec<'a> {
    pub oid: [u8; 20],
    pub offset: u64,
    pub entry_bytes: &'a [u8],
}

pub fn build_idx(pack: &[u8], specs: &[IdxSpec<'_>]) -> Vec<u8> {
    let n = specs.len();
    let mut names: Vec<&[u8; 20]> = specs.iter().map(|s| &s.oid).collect();
    names.sort_by(|a, b| a.cmp(b));
    let by_oid: std::collections::HashMap<[u8; 20], (u64, &[u8])> = specs
        .iter()
        .map(|s| (s.oid, (s.offset, s.entry_bytes)))
        .collect();
    let mut out = Vec::new();
    out.extend_from_slice(&[0xff, 0x74, 0x4f, 0x63]);
    out.extend_from_slice(&2u32.to_be_bytes());
    let mut fanout = [0u32; 256];
    for oid in &names {
        fanout[oid[0] as usize] += 1;
    }
    let mut acc = 0u32;
    for i in 0..256 {
        acc += fanout[i];
        out.extend_from_slice(&acc.to_be_bytes());
    }
    for oid in &names {
        out.extend_from_slice(oid.as_slice());
    }
    let crc_start = out.len();
    for _ in 0..n {
        out.extend_from_slice(&0u32.to_be_bytes());
    }
    let mut crcs: Vec<u32> = Vec::with_capacity(n);
    for oid in &names {
        let (offset, entry_bytes) = by_oid[*oid];
        let start = offset as usize;
        let crc = crc32fast::hash(&pack[start..start + entry_bytes.len()]);
        crcs.push(crc);
    }
    out[crc_start..crc_start + 4 * n].copy_from_slice(
        &crcs
            .iter()
            .flat_map(|c| c.to_be_bytes())
            .collect::<Vec<u8>>(),
    );
    for oid in &names {
        out.extend_from_slice(&(by_oid[*oid].0 as u32).to_be_bytes());
    }
    out.extend_from_slice(&pack[pack.len() - 20..]);
    let mut h = Sha1::new();
    h.update(&out);
    let sha: [u8; 20] = h.finalize().into();
    out.extend_from_slice(&sha);
    out
}

pub fn loose_object(type_name: &str, content: &[u8]) -> Vec<u8> {
    zlib(&object(type_name, content).0)
}

pub fn temp_db(test_name: &str) -> (tempfile::TempDir, rusqlite::Connection) {
    let dir = tempfile::tempdir().expect("tempdir");
    let _ = test_name;
    let conn = pack_microscope::store::open(&dir.path().join("t.db")).expect("open");
    (dir, conn)
}
