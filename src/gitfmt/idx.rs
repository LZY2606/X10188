use super::oid::Oid;
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: Oid,
    pub crc32: u32,
    pub offset: u64,
    pub huge: bool,
}

#[derive(Debug, Clone)]
pub struct IdxData {
    pub entries: Vec<IdxEntry>,
    pub fanout: Vec<u32>,
    pub pack_checksum: Option<Oid>,
    pub idx_checksum: Option<Oid>,
    pub checksum_ok: bool,
    pub index_checksum_ok: bool,
}

fn be_u32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}
fn be_u64(b: &[u8]) -> u64 {
    u64::from_be_bytes([
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
    ])
}

fn sha1_of(data: &[u8]) -> Oid {
    let mut h = Sha1::new();
    h.update(data);
    let r = h.finalize();
    let mut o = [0u8; 20];
    o.copy_from_slice(&r);
    Oid(o)
}

/// Parse an idx v2 file, including fanout table and both trailing checksums.
pub fn parse_idx(data: &[u8]) -> Result<IdxData, String> {
    if data.len() < 8 {
        return Err("idx too short".into());
    }
    if &data[..4] != b"\xff\x74\x4f\x63" {
        return Err("idx v2 magic missing (v1 idx unsupported)".into());
    }
    if be_u32(&data[4..8]) != 2 {
        return Err("unsupported idx version".into());
    }
    let mut fanout = Vec::with_capacity(256);
    let fo = 8;
    for i in 0..256 {
        fanout.push(be_u32(&data[fo + i * 4..fo + i * 4 + 4]));
    }
    let n = *fanout.last().unwrap() as usize;
    let mut p = fo + 256 * 4;
    let need = p + n * 20 + n * 4 + n * 4;
    if data.len() < need + 40 {
        return Err("idx tables truncated".into());
    }
    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        let mut o = [0u8; 20];
        o.copy_from_slice(&data[p..p + 20]);
        p += 20;
        oids.push(Oid(o));
    }
    let mut crcs = Vec::with_capacity(n);
    for _ in 0..n {
        crcs.push(be_u32(&data[p..p + 4]));
        p += 4;
    }
    let mut offs = Vec::with_capacity(n);
    let mut huge_index: Vec<usize> = Vec::new();
    for i in 0..n {
        let v = be_u32(&data[p..p + 4]);
        p += 4;
        if v & 0x8000_0000 != 0 {
            huge_index.push(i);
            offs.push(v & 0x7fff_ffff);
        } else {
            offs.push(v as u64);
        }
    }
    for &i in &huge_index {
        let slot = offs[i] as usize;
        let at = p + slot * 8;
        if at + 8 > data.len() - 40 {
            return Err("idx 64-bit offset table truncated".into());
        }
        offs[i] = be_u64(&data[at..at + 8]);
    }
    p += huge_index.len() * 0;
    // Skip past any 64-bit offset table region implicitly; checksums are at end.
    let pack_checksum = {
        let mut o = [0u8; 20];
        o.copy_from_slice(&data[data.len() - 40..data.len() - 20]);
        Oid(o)
    };
    let idx_checksum = {
        let mut o = [0u8; 20];
        o.copy_from_slice(&data[data.len() - 20..]);
        Oid(o)
    };
    let checksum_ok = sha1_of(&data[..data.len() - 20]) == idx_checksum;
    let entries = (0..n)
        .map(|i| IdxEntry {
            oid: oids[i],
            crc32: crcs[i],
            offset: offs[i],
            huge: huge_index.contains(&i),
        })
        .collect();
    Ok(IdxData {
        entries,
        fanout,
        pack_checksum: Some(pack_checksum),
        idx_checksum: Some(idx_checksum),
        checksum_ok,
        index_checksum_ok: checksum_ok,
    })
}

/// SHA1 of a whole pack file (for matching idx <-> pack).
pub fn pack_sha1(data: &[u8]) -> Oid {
    sha1_of(data)
}

/// Check the pack's own trailing checksum: SHA1 over all bytes except the
/// final 20 must equal those final 20 bytes.
pub fn pack_trailer_ok(data: &[u8]) -> (Option<Oid>, bool) {
    if data.len() < 32 {
        return (None, false);
    }
    let calc = sha1_of(&data[..data.len() - 20]);
    let mut o = [0u8; 20];
    o.copy_from_slice(&data[data.len() - 20..]);
    let stored = Oid(o);
    (Some(calc), calc == stored)
}
