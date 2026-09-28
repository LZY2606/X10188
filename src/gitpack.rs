//! Minimal Git pack / idx builders used by tests and useful for generating
//! synthetic forensic samples without invoking system git.

use crate::gitcore::{encode_ofs_distance, git_oid, read_size_encoding, write_size_encoding, zlib_compress};

pub const T_COMMIT: u8 = 1;
pub const T_TREE: u8 = 2;
pub const T_BLOB: u8 = 3;
pub const T_TAG: u8 = 4;
pub const T_OFS: u8 = 6;
pub const T_REF: u8 = 7;

#[derive(Clone)]
pub enum EntrySpec {
    Full {
        obj_type: u8,
        content: Vec<u8>,
    },
    Ofs {
        base_index: usize,
        delta: Vec<u8>,
        result_size: u64,
        base_size: u64,
    },
    Ref {
        base_oid: [u8; 20],
        delta: Vec<u8>,
        result_size: u64,
        base_size: u64,
    },
}

pub struct BuiltEntry {
    pub offset: usize,
    pub z_data: Vec<u8>,
    pub hdr_len: usize,
    pub oid: Option<[u8; 20]>,
}

pub struct BuiltPack {
    pub data: Vec<u8>,
    pub entries: Vec<BuiltEntry>,
    pub checksum: [u8; 20],
    pub count: usize,
}

fn type_name(t: u8) -> &'static str {
    match t {
        1 => "commit",
        2 => "tree",
        3 => "blob",
        4 => "tag",
        _ => panic!("bad type"),
    }
}

fn oid_bytes(s: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}

pub fn make_delta(base: &[u8], inserts: &[(usize, &[u8])], result_size_hint: Option<u64>) -> Vec<u8> {
    // Simple builder: build result by copies + inserts in order.
    let mut delta = Vec::new();
    write_size_encoding(base.len() as u64, &mut delta);
    let result_len = result_size_hint.unwrap_or_else(|| {
        let mut l = base.len() as u64;
        for (_, d) in inserts {
            l += d.len() as u64;
        }
        l
    });
    write_size_encoding(result_len, &mut delta);
    let mut pos = 0usize;
    for (at, data) in inserts {
        if *at > pos {
            let chunk = at - pos;
            emit_copy(&mut delta, pos as u32, chunk as u32);
            pos = *at;
        }
        assert!(*at == pos || *at >= pos);
        emit_insert(&mut delta, data);
    }
    if pos < base.len() {
        emit_copy(&mut delta, pos as u32, (base.len() - pos) as u32);
    }
    delta
}

fn emit_copy(delta: &mut Vec<u8>, offset: u32, size: u32) {
    let mut op = 0x80u8;
    let mut args = Vec::new();
    for i in 0..4u8 {
        let b = ((offset >> (8 * i)) & 0xff) as u8;
        if b != 0 {
            op |= 1 << i;
            args.push(b);
        }
    }
    let size = if size == 0x10000 { 0 } else { size };
    for i in 0..3u8 {
        let b = ((size >> (8 * i)) & 0xff) as u8;
        if b != 0 {
            op |= 1 << (4 + i);
            args.push(b);
        }
    }
    delta.push(op);
    delta.extend_from_slice(&args);
}

fn emit_insert(delta: &mut Vec<u8>, data: &[u8]) {
    assert!(!data.is_empty() && data.len() <= 127);
    delta.push(data.len() as u8);
    delta.extend_from_slice(data);
}

pub fn build_pack(specs: &[EntrySpec]) -> BuiltPack {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"PACK");
    data.extend_from_slice(&2u32.to_be_bytes());
    data.extend_from_slice(&(specs.len() as u32).to_be_bytes());

    let mut built: Vec<BuiltEntry> = Vec::new();
    // first pass needs base offsets for ofs; build sequentially
    let mut resolved_contents: Vec<Vec<u8>> = Vec::new();
    let mut resolved_types: Vec<u8> = Vec::new();

    for (idx, spec) in specs.iter().enumerate() {
        let offset = data.len();
        match spec {
            EntrySpec::Full { obj_type, content } => {
                let mut hdr = vec![((*obj_type & 0x7) << 4) as u8];
                hdr[0] |= (content.len() & 0x7f) as u8;
                let mut rest = (content.len() >> 7) as u64;
                while rest > 0 {
                    let last = hdr.last_mut().unwrap();
                    *last |= 0x80;
                    hdr.push((rest & 0x7f) as u8);
                    rest >>= 7;
                }
                let hdr_len = hdr.len();
                data.extend_from_slice(&hdr);
                let z = zlib_compress(content);
                data.extend_from_slice(&z);
                let oid_hex = git_oid(type_name(*obj_type), content);
                built.push(BuiltEntry {
                    offset,
                    z_data: z,
                    hdr_len,
                    oid: Some(oid_bytes(&oid_hex)),
                });
                resolved_contents.push(content.clone());
                resolved_types.push(*obj_type);
            }
            EntrySpec::Ofs {
                base_index,
                delta,
                result_size: _,
                base_size: _,
            } => {
                let base_offset = built[*base_index].offset;
                let distance = (offset - base_offset) as u64;
                let encoded = encode_ofs_distance(distance);
                let mut hdr = vec![(T_OFS << 4) | ((delta.len() & 0x7f) as u8)];
                let mut rest = (delta.len() >> 7) as u64;
                while rest > 0 {
                    let last = hdr.last_mut().unwrap();
                    *last |= 0x80;
                    hdr.push((rest & 0x7f) as u8);
                    rest >>= 7;
                }
                let hdr_len = hdr.len() + encoded.len();
                data.extend_from_slice(&hdr);
                data.extend_from_slice(&encoded);
                let z = zlib_compress(delta);
                data.extend_from_slice(&z);
                built.push(BuiltEntry {
                    offset,
                    z_data: z,
                    hdr_len,
                    oid: None,
                });
                let out = crate::gitcore::apply_delta(&resolved_contents[*base_index], delta, u64::MAX)
                    .unwrap()
                    .output;
                resolved_contents.push(out);
                resolved_types.push(resolved_types[*base_index]);
                let _ = idx;
            }
            EntrySpec::Ref {
                base_oid,
                delta,
                result_size: _,
                base_size: _,
            } => {
                let mut hdr = vec![(T_REF << 4) | ((delta.len() & 0x7f) as u8)];
                let mut rest = (delta.len() >> 7) as u64;
                while rest > 0 {
                    let last = hdr.last_mut().unwrap();
                    *last |= 0x80;
                    hdr.push((rest & 0x7f) as u8);
                    rest >>= 7;
                }
                let hdr_len = hdr.len() + 20;
                data.extend_from_slice(&hdr);
                data.extend_from_slice(base_oid);
                let z = zlib_compress(delta);
                data.extend_from_slice(&z);
                built.push(BuiltEntry {
                    offset,
                    z_data: z,
                    hdr_len,
                    oid: None,
                });
                // find base content from prior resolved entries by oid
                let base_idx = built
                    .iter()
                    .position(|b| b.oid.as_ref() == Some(base_oid))
                    .expect("ref base must be a prior full entry in builder");
                let out = crate::gitcore::apply_delta(&resolved_contents[base_idx], delta, u64::MAX)
                    .unwrap()
                    .output;
                resolved_contents.push(out);
                resolved_types.push(resolved_types[base_idx]);
            }
        }
    }

    // Fill in delta oids (for idx building convenience).
    for (i, b) in built.iter_mut().enumerate() {
        if b.oid.is_none() {
            let hex = git_oid(type_name(resolved_types[i]), &resolved_contents[i]);
            b.oid = Some(oid_bytes(&hex));
        }
    }

    let checksum_hex = crate::gitcore::sha1_hex(&data);
    let checksum = oid_bytes(&checksum_hex);
    data.extend_from_slice(&checksum);
    BuiltPack {
        data,
        entries: built,
        checksum,
        count: specs.len(),
    }
}

pub struct IdxOptions {
    pub corrupt_crc_index: Option<usize>,
    pub wrong_pack_checksum: bool,
    pub corrupt_self_checksum: bool,
    pub offset_override: Vec<(usize, u64)>,
}

impl Default for IdxOptions {
    fn default() -> Self {
        IdxOptions {
            corrupt_crc_index: None,
            wrong_pack_checksum: false,
            corrupt_self_checksum: false,
            offset_override: Vec::new(),
        }
    }
}

pub fn build_idx(pack: &BuiltPack, opts: &IdxOptions) -> Vec<u8> {
    use crate::gitcore::crc32;
    let n = pack.entries.len();
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&[0xff, 0x74, 0x4f, 0x63]);
    out.extend_from_slice(&2u32.to_be_bytes());

    // fanout
    let mut counts = [0u32; 256];
    let mut sorted: Vec<usize> = (0..n).collect();
    sorted.sort_by(|&a, &b| pack.entries[a].oid.unwrap().cmp(&pack.entries[b].oid.unwrap()));
    for &i in &sorted {
        counts[pack.entries[i].oid.unwrap()[0] as usize] += 1;
    }
    let mut cum = 0u32;
    for c in counts.iter() {
        cum += c;
        out.extend_from_slice(&cum.to_be_bytes());
    }
    // names sorted
    for &i in &sorted {
        out.extend_from_slice(&pack.entries[i].oid.unwrap());
    }
    // crc table: CRC over header+zdata of entry inside pack
    let crcs: Vec<u32> = (0..n)
        .map(|i| {
            if Some(i) == opts.corrupt_crc_index {
                0xdead_beef
            } else {
                let e = &pack.entries[i];
                let start = e.offset;
                let end = start + e.hdr_len + e.z_data.len();
                crc32(&pack.data[start..end])
            }
        })
        .collect();
    for c in &crcs {
        out.extend_from_slice(&c.to_be_bytes());
    }
    // offsets
    for &i in &sorted {
        let mut off = pack.entries[i].offset as u64;
        for (idx, val) in &opts.offset_override {
            if *idx == i {
                off = *val;
            }
        }
        out.extend_from_slice(&(off as u32).to_be_bytes());
    }
    // pack checksum
    if opts.wrong_pack_checksum {
        out.extend_from_slice(&[0x11; 20]);
    } else {
        out.extend_from_slice(&pack.checksum);
    }
    // self checksum over everything so far
    let chk = crate::gitcore::sha1_hex(&out);
    let mut bytes = [0u8; 20];
    for i in 0..20 {
        bytes[i] = u8::from_str_radix(&chk[i * 2..i * 2 + 2], 16).unwrap();
    }
    if opts.corrupt_self_checksum {
        bytes[0] ^= 0xff;
    }
    out.extend_from_slice(&bytes);
    out
}

/// Rebuild a pack but tweak one entry's declared size field to lie.
pub fn build_pack_with_spoofed_size(
    obj_type: u8,
    content: &[u8],
    declared_size: usize,
) -> Vec<u8> {
    let mut data: Vec<u8> = Vec::new();
    data.extend_from_slice(b"PACK");
    data.extend_from_slice(&2u32.to_be_bytes());
    data.extend_from_slice(&1u32.to_be_bytes());
    let mut hdr = vec![(obj_type << 4) | ((declared_size & 0x7f) as u8)];
    let mut rest = (declared_size >> 7) as u64;
    while rest > 0 {
        let last = hdr.last_mut().unwrap();
        *last |= 0x80;
        hdr.push((rest & 0x7f) as u8);
        rest >>= 7;
    }
    data.extend_from_slice(&hdr);
    data.extend_from_slice(&zlib_compress(content));
    let chk = crate::gitcore::sha1_hex(&data);
    for i in 0..20 {
        data.push(u8::from_str_radix(&chk[i * 2..i * 2 + 2], 16).unwrap());
    }
    data
}

pub fn loose_object(obj_type: &str, content: &[u8]) -> Vec<u8> {
    let mut store = Vec::new();
    store.extend_from_slice(obj_type.as_bytes());
    store.push(b' ');
    store.extend_from_slice(content.len().to_string().as_bytes());
    store.push(0);
    store.extend_from_slice(content);
    zlib_compress(&store)
}

#[allow(dead_code)]
fn _check_readback(data: &[u8]) -> u64 {
    let mut pos = 0;
    read_size_encoding(data, &mut pos).unwrap()
}
