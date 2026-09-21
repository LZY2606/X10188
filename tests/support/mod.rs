//! Self-contained Git pack/idx fixture builder. Never shells out to git.

use flate2::write::ZlibEncoder;
use flate2::Compression;
use sha1::{Digest, Sha1};
use std::io::Write;

pub fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

pub fn git_oid(kind: &str, payload: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{kind} {}\0", payload.len()).as_bytes());
    h.update(payload);
    hex::encode(h.finalize())
}

pub fn git_frame(kind: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("{kind} {}\0", payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// Pack entry header (size = base-128 MSB-first).
pub fn entry_header(kind_code: u8, size: usize) -> Vec<u8> {
    let mut bytes = vec![(kind_code << 4) | ((size as u8) & 0x0f)];
    let mut s = size >> 4;
    while s > 0 {
        bytes[0] |= 0x80;
        let mut b = (s & 0x7f) as u8;
        s >>= 7;
        if s > 0 {
            b |= 0x80;
        }
        bytes.push(b);
    }
    bytes
}

#[derive(Clone)]
pub enum Entry {
    Plain { kind: String, payload: Vec<u8> },
    Ref { base_oid: String, delta: Vec<u8> },
    Ofs { distance: usize, delta: Vec<u8>, base_oid: String },
}

pub struct BuiltPack {
    pub data: Vec<u8>,
    pub entries: Vec<PackEntryInfo>,
}

#[derive(Clone)]
pub struct PackEntryInfo {
    pub oid: String,
    pub header_offset: usize,
    pub kind: String,
    pub crc32: u32,
}

pub fn build_pack(entries: &[Entry]) -> BuiltPack {
    let mut body: Vec<u8> = b"PACK".to_vec();
    body.extend_from_slice(&2u32.to_be_bytes());
    body.extend_from_slice(&(entries.len() as u32).to_be_bytes());

    let mut infos = Vec::new();
    // first pass layout, computing oids needs base sizes known.
    // We resolve payloads up front.
    let mut payloads: Vec<(String, Vec<u8>)> = Vec::new();
    for e in entries {
        match e {
            Entry::Plain { kind, payload } => {
                let oid = git_oid(kind, payload);
                payloads.push((oid, payload.clone()));
            }
            Entry::Ref { delta, .. } | Entry::Ofs { delta, .. } => {
                // placeholder; filled below using running data
                payloads.push((String::new(), delta.clone()));
            }
        }
    }

    let mut resolved: Vec<(String, String, Vec<u8>)> = Vec::new();
    // (oid, type, final payload)
    for (i, e) in entries.iter().enumerate() {
        let header_offset = body.len();
        match e {
            Entry::Plain { kind, payload } => {
                let code = match kind.as_str() {
                    "commit" => 1,
                    "tree" => 2,
                    "blob" => 3,
                    "tag" => 4,
                    _ => panic!("bad kind"),
                };
                let comp = zlib(payload);
                let hdr = entry_header(code, payload.len());
                let crc = crc32fast::hash(&{
                    let mut v = hdr.clone();
                    v.extend_from_slice(&comp);
                    v
                });
                body.extend_from_slice(&hdr);
                body.extend_from_slice(&comp);
                let oid = git_oid(kind, payload);
                infos.push(PackEntryInfo {
                    oid: oid.clone(),
                    header_offset,
                    kind: kind.clone(),
                    crc32: crc,
                });
                resolved.push((oid, kind.clone(), payload.clone()));
            }
            Entry::Ref { base_oid, delta } => {
                let (base_type, _base_payload, out_payload) =
                    resolve_delta(&resolved, &payloads, entries, base_oid, delta);
                let comp = zlib(delta);
                let hdr = entry_header(7, delta.len());
                let crc = crc32fast::hash(&{
                    let mut v = hdr.clone();
                    v.extend_from_slice(&hex::decode(base_oid).unwrap());
                    v.extend_from_slice(&comp);
                    v
                });
                body.extend_from_slice(&hdr);
                body.extend_from_slice(&hex::decode(base_oid).unwrap());
                body.extend_from_slice(&comp);
                let oid = git_oid(&base_type, &out_payload);
                infos.push(PackEntryInfo {
                    oid: oid.clone(),
                    header_offset,
                    kind: "ref-delta".into(),
                    crc32: crc,
                });
                resolved.push((oid, base_type, out_payload));
            }
            Entry::Ofs {
                distance,
                delta,
                base_oid,
            } => {
                let (base_type, _base_payload, out_payload) =
                    resolve_delta(&resolved, &payloads, entries, base_oid, delta);
                let comp = zlib(delta);
                let hdr = entry_header(6, delta.len());
                let ofs = ofs_encode(*distance);
                let crc = crc32fast::hash(&{
                    let mut v = hdr.clone();
                    v.extend_from_slice(&ofs);
                    v.extend_from_slice(&comp);
                    v
                });
                body.extend_from_slice(&hdr);
                body.extend_from_slice(&ofs);
                body.extend_from_slice(&comp);
                let oid = git_oid(&base_type, &out_payload);
                infos.push(PackEntryInfo {
                    oid: oid.clone(),
                    header_offset,
                    kind: "ofs-delta".into(),
                    crc32: crc,
                });
                resolved.push((oid, base_type, out_payload));
            }
        }
        let _ = i;
    }

    // pack trailer: sha1 of pack without trailer
    let checksum = {
        let mut h = Sha1::new();
        h.update(&body);
        let out = h.finalize();
        out.to_vec()
    };
    body.extend_from_slice(&checksum);
    BuiltPack {
        data: body,
        entries: infos,
    }
}

fn ofs_encode(mut dist: usize) -> Vec<u8> {
    let mut bytes = vec![(dist & 0x7f) as u8];
    dist >>= 7;
    while dist > 0 {
        dist -= 1;
        bytes.push((dist & 0x7f) as u8);
        dist >>= 7;
    }
    bytes.reverse();
    for b in bytes.iter_mut().skip(1) {
        *b |= 0x80;
    }
    bytes
}

fn resolve_delta(
    resolved: &[(String, String, Vec<u8>)],
    _payloads: &[(String, Vec<u8>)],
    _entries: &[Entry],
    base_oid: &str,
    delta: &[u8],
) -> (String, Vec<u8>, Vec<u8>) {
    let (base_type, base_payload) = resolved
        .iter()
        .find(|(oid, _, _)| oid == base_oid)
        .map(|(_, t, p)| (t.clone(), p.clone()))
        .unwrap_or_else(|| panic!("fixture base {base_oid} not found"));
    let out = apply_delta_fixture(&base_payload, delta);
    (base_type, base_payload, out)
}

pub fn apply_delta_fixture(base: &[u8], delta: &[u8]) -> Vec<u8> {
    let (bs, mut pos) = read_var(delta, 0);
    let (ts, p2) = read_var(delta, pos);
    pos = p2;
    assert_eq!(bs, base.len());
    let mut out = Vec::with_capacity(ts);
    while pos < delta.len() {
        let op = delta[pos];
        pos += 1;
        if op & 0x80 != 0 {
            let mut off = 0usize;
            let mut size = 0usize;
            for (i, shift) in [0u32, 8, 16, 24].iter().enumerate() {
                if op & (1 << i) != 0 {
                    off |= (delta[pos] as usize) << shift;
                    pos += 1;
                }
            }
            for (i, shift) in [0u32, 8, 16].iter().enumerate() {
                if op & (1 << (4 + i)) != 0 {
                    size |= (delta[pos] as usize) << shift;
                    pos += 1;
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            out.extend_from_slice(&base[off..off + size]);
        } else {
            let len = op as usize;
            out.extend_from_slice(&delta[pos..pos + len]);
            pos += len;
        }
    }
    assert_eq!(out.len(), ts);
    out
}

pub fn read_var(buf: &[u8], mut pos: usize) -> (usize, usize) {
    let mut size = 0;
    let mut shift = 0;
    loop {
        let b = buf[pos];
        pos += 1;
        size |= ((b & 0x7f) as usize) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
    }
    (size, pos)
}

/// Encode an internal delta that copies `copy` ranges from base and inserts literals.
pub fn delta_with(base_len: usize, target_len: usize, body: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    write_var(&mut out, base_len);
    write_var(&mut out, target_len);
    out.extend_from_slice(&body);
    out
}

fn write_var(buf: &mut Vec<u8>, mut n: usize) {
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        buf.push(b);
        if n == 0 {
            break;
        }
    }
}

pub fn copy_op(offset: usize, size: usize) -> Vec<u8> {
    let mut cp = 0x80u8;
    let mut body = Vec::new();
    for i in 0..4 {
        let byte = (offset >> (8 * i)) & 0xff;
        if byte != 0 {
            cp |= 1 << i;
            body.push(byte as u8);
        }
    }
    for i in 0..3 {
        let byte = (size >> (8 * i)) & 0xff;
        if byte != 0 {
            cp |= 1 << (4 + i);
            body.push(byte as u8);
        }
    }
    let mut out = vec![cp];
    out.extend_from_slice(&body);
    out
}

pub fn insert_op(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for chunk in data.chunks(127) {
        out.push(chunk.len() as u8);
        out.extend_from_slice(chunk);
    }
    out
}

/// Build idx v2 for a built pack.
pub fn build_idx(infos: &[PackEntryInfo], pack_sha: &[u8]) -> Vec<u8> {
    let mut sorted: Vec<&PackEntryInfo> = infos.iter().collect();
    sorted.sort_by(|a, b| a.oid.cmp(&b.oid));
    let n = sorted.len();
    let mut data = Vec::new();
    data.extend_from_slice(b"\xfftOc");
    data.extend_from_slice(&2u32.to_be_bytes());
    let mut fanout = vec![0u32; 256];
    for e in &sorted {
        let first = hex::decode(&e.oid).unwrap()[0] as usize;
        for i in first..256 {
            fanout[i] += 1;
        }
    }
    for f in &fanout {
        data.extend_from_slice(&f.to_be_bytes());
    }
    for e in &sorted {
        data.extend_from_slice(&hex::decode(&e.oid).unwrap());
    }
    for e in &sorted {
        data.extend_from_slice(&e.crc32.to_be_bytes());
    }
    for e in &sorted {
        data.extend_from_slice(&(e.header_offset as u32).to_be_bytes());
    }
    data.extend_from_slice(pack_sha);
    let idx_sha = {
        let mut h = Sha1::new();
        h.update(&data);
        h.finalize().to_vec()
    };
    data.extend_from_slice(&idx_sha);
    data
}

pub fn pack_sha(data_without_trailer: &[u8]) -> Vec<u8> {
    let mut h = Sha1::new();
    h.update(data_without_trailer);
    h.finalize().to_vec()
}
