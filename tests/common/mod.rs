//! Synthetic, hand-built Git objects/packs. No system git anywhere.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use microscope::git::{crc32, git_oid, Kind};

pub fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    std::io::Write::write_all(&mut e, data).unwrap();
    e.finish().unwrap()
}

pub fn loose_object(kind: Kind, content: &[u8]) -> Vec<u8> {
    let mut full = format!("{} {}\0", kind.name(), content.len()).into_bytes();
    full.extend_from_slice(content);
    deflate(&full)
}

pub fn write_size(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

#[derive(Clone)]
pub enum DeltaOp {
    Copy(usize, usize), // offset, len
    Insert(Vec<u8>),
}

pub fn encode_delta(base_len: usize, ops: &[DeltaOp]) -> Vec<u8> {
    let mut d = Vec::new();
    write_size(&mut d, base_len as u64);
    let result_len: usize = ops
        .iter()
        .map(|o| match o {
            DeltaOp::Copy(_, l) => *l,
            DeltaOp::Insert(b) => b.len(),
        })
        .sum();
    write_size(&mut d, result_len as u64);
    for op in ops {
        match op {
            DeltaOp::Insert(data) => {
                assert!(data.len() < 128, "test inserts fit one opcode");
                d.push(data.len() as u8);
                d.extend_from_slice(data);
            }
            DeltaOp::Copy(off, len) => {
                let mut b = 0x80u8;
                let mut operands = Vec::new();
                for i in 0..4u32 {
                    let byte = ((*off >> (8 * i)) & 0xff) as u8;
                    if byte != 0 {
                        b |= 1 << i;
                        operands.push(byte);
                    }
                }
                for i in 0..3u32 {
                    let byte = ((*len >> (8 * i)) & 0xff) as u8;
                    if byte != 0 {
                        b |= 1 << (4 + i);
                        operands.push(byte);
                    }
                }
                d.push(b);
                d.extend(operands);
            }
        }
    }
    d
}

pub fn ofs_header(mut neg: u64) -> Vec<u8> {
    let mut bytes = vec![(neg & 0x7f) as u8];
    neg >>= 7;
    while neg > 0 {
        neg -= 1;
        bytes.push((0x80 | (neg & 0x7f)) as u8);
        neg >>= 7;
    }
    bytes.reverse();
    bytes
}

pub fn pack_header(out: &mut Vec<u8>, type_code: u8, size: u64) {
    let mut b = (type_code << 4) | ((size as u8) & 0x0f);
    let mut v = size >> 4;
    if v != 0 {
        b |= 0x80;
    }
    out.push(b);
    while v != 0 {
        let mut nb = (v & 0x7f) as u8;
        v >>= 7;
        if v != 0 {
            nb |= 0x80;
        }
        out.push(nb);
    }
}

#[derive(Clone)]
pub enum PackObj {
    Full(Kind, Vec<u8>),
    Ofs { neg: u64, delta: Vec<u8>, result: (Kind, Vec<u8>) },
    Ref { base_oid: String, delta: Vec<u8>, result: (Kind, Vec<u8>) },
}

pub struct BuiltPack {
    pub bytes: Vec<u8>,
    pub idx: Vec<u8>,
    pub offsets: Vec<u64>,
    pub oids: Vec<String>,
    /// (offset, header_len, compressed_len, expected crc)
    pub spans: Vec<(u64, usize, usize, u32)>,
}

pub fn build_pack(objs: &[PackObj]) -> BuiltPack {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(b"PACK");
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&(objs.len() as u32).to_be_bytes());

    let mut offsets = Vec::new();
    let mut prefix_lens = Vec::new(); // header + ofs/ref prefix
    let mut zs: Vec<Vec<u8>> = Vec::new();
    let mut oids = Vec::new();

    for o in objs {
        let offset = body.len() as u64;
        offsets.push(offset);
        match o {
            PackObj::Full(kind, content) => {
                pack_header(&mut body, code(*kind), content.len() as u64);
                prefix_lens.push(body.len() - offset as usize);
                let z = deflate(content);
                body.extend_from_slice(&z);
                zs.push(z);
                oids.push(git_oid(*kind, content));
            }
            PackObj::Ofs { neg, delta, result } => {
                pack_header(&mut body, 6, delta.len() as u64);
                body.extend_from_slice(&ofs_header(*neg));
                prefix_lens.push(body.len() - offset as usize);
                let z = deflate(delta);
                body.extend_from_slice(&z);
                zs.push(z);
                oids.push(git_oid(result.0, &result.1));
            }
            PackObj::Ref { base_oid, delta, result } => {
                pack_header(&mut body, 7, delta.len() as u64);
                body.extend_from_slice(&hex::decode(base_oid).unwrap());
                prefix_lens.push(body.len() - offset as usize);
                let z = deflate(delta);
                body.extend_from_slice(&z);
                zs.push(z);
                oids.push(git_oid(result.0, &result.1));
            }
        }
    }

    // CRC spans before appending the checksum
    let mut spans = Vec::new();
    for i in 0..objs.len() {
        let off = offsets[i];
        let plen = prefix_lens[i];
        let zlen = zs[i].len();
        let crc = crc32(&body[off as usize..off as usize + plen + zlen]);
        spans.push((off, plen, zlen, crc));
    }

    let pack_sha = {
        use sha1::Digest;
        let mut h = sha1::Sha1::new();
        h.update(&body);
        let d = h.finalize();
        body.extend_from_slice(&d);
        hex::encode(d)
    };

    // idx v2 sorted by oid (as git requires)
    let mut order: Vec<usize> = (0..objs.len()).collect();
    order.sort_by(|a, b| oids[*a].cmp(&oids[*b]));
    let mut fanout = [0u32; 256];
    for o in &oids {
        fanout[hex::decode(o).unwrap()[0] as usize] += 1;
    }

    let mut idx = Vec::new();
    idx.extend_from_slice(b"\xfftOc");
    idx.extend_from_slice(&2u32.to_be_bytes());
    let mut cum = 0u32;
    for c in fanout {
        cum += c;
        idx.extend_from_slice(&cum.to_be_bytes());
    }
    for i in &order {
        idx.extend_from_slice(&hex::decode(&oids[*i]).unwrap());
    }
    for i in &order {
        idx.extend_from_slice(&spans[*i].3.to_be_bytes());
    }
    for i in &order {
        idx.extend_from_slice(&(offsets[*i] as u32).to_be_bytes());
    }
    idx.extend_from_slice(&hex::decode(&pack_sha).unwrap());
    let idx_sha = {
        use sha1::Digest;
        let mut h = sha1::Sha1::new();
        h.update(&idx);
        let d = h.finalize();
        idx.extend_from_slice(&d);
        hex::encode(d)
    };
    let _ = idx_sha;

    BuiltPack { bytes: body, idx, offsets, oids, spans }
}

fn code(kind: Kind) -> u8 {
    match kind {
        Kind::Commit => 1,
        Kind::Tree => 2,
        Kind::Blob => 3,
        Kind::Tag => 4,
    }
}

pub fn temp_app(test_name: &str) -> microscope::AppState {
    let dir = std::env::temp_dir().join(format!(
        "microscope-test-{}-{}",
        test_name,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    microscope::AppState::open(&dir).unwrap()
}
