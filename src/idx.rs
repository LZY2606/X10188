//! Git pack index (.idx) 解析：v2（magic \xfftOc）与 v1，fanout 表、oid、CRC32、偏移。
use crate::gitutil;

#[derive(Clone, Debug)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug)]
pub struct IdxParse {
    pub version: u32,
    pub fanout: Vec<u32>,
    pub entries: Vec<IdxEntry>,
    pub pack_checksum: String,
    pub checksum_ok: bool,
    pub error: Option<String>,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub fn parse_idx(data: &[u8]) -> IdxParse {
    let mut r = IdxParse {
        version: 1,
        fanout: vec![0; 256],
        entries: Vec::new(),
        pack_checksum: String::new(),
        checksum_ok: true,
        error: None,
    };
    if data.len() >= 8 && &data[0..4] == b"\xfftOc" {
        r.version = be32(&data[4..8]);
        if r.version != 2 {
            r.error = Some(format!("unsupported idx version {}", r.version));
            return r;
        }
        if data.len() < 8 + 1024 + 40 {
            r.error = Some("idx v2 truncated".into());
            return r;
        }
        let mut off = 8usize;
        for i in 0..256 {
            r.fanout[i] = be32(&data[off + i * 4..]);
        }
        off += 1024;
        let n = r.fanout[255] as usize;
        if off + 20 * n + 4 * n + 4 * n + 40 > data.len() {
            r.error = Some("idx v2 truncated in entries".into());
            return r;
        }
        let mut oids = Vec::with_capacity(n);
        for i in 0..n {
            oids.push(gitutil::to_hex(&data[off + i * 20..off + i * 20 + 20]));
        }
        off += 20 * n;
        let mut crcs = Vec::with_capacity(n);
        for i in 0..n {
            crcs.push(be32(&data[off + i * 4..]));
        }
        off += 4 * n;
        let mut offs32 = Vec::with_capacity(n);
        for i in 0..n {
            offs32.push(be32(&data[off + i * 4..]));
        }
        off += 4 * n;
        let large_base = off;
        for i in 0..n {
            let v = offs32[i];
            let offset = if v & 0x8000_0000 != 0 {
                let li = (v & 0x7fff_ffff) as usize;
                let p = large_base + li * 8;
                if p + 8 > data.len() {
                    r.error = Some("idx large-offset table out of range".into());
                    return r;
                }
                u64::from_be_bytes(data[p..p + 8].try_into().unwrap())
            } else {
                v as u64
            };
            r.entries.push(IdxEntry { oid: oids[i].clone(), crc32: crcs[i], offset });
        }
        r.pack_checksum = gitutil::to_hex(&data[data.len() - 40..data.len() - 20]);
        r.checksum_ok =
            gitutil::sha1_hex(&data[..data.len() - 20]) == gitutil::to_hex(&data[data.len() - 20..]);
    } else {
        // v1：fanout 后直接跟 (offset, oid) 记录
        if data.len() < 1024 {
            r.error = Some("idx v1 truncated".into());
            return r;
        }
        for i in 0..256 {
            r.fanout[i] = be32(&data[i * 4..]);
        }
        for w in r.fanout.windows(2) {
            if w[0] > w[1] {
                r.error = Some("fanout not monotonic".into());
                return r;
            }
        }
        let n = r.fanout[255] as usize;
        if 1024 + n * 24 != data.len() {
            r.error = Some("idx v1 size mismatch".into());
            return r;
        }
        for i in 0..n {
            let p = 1024 + i * 24;
            r.entries.push(IdxEntry {
                offset: be32(&data[p..]) as u64,
                oid: gitutil::to_hex(&data[p + 4..p + 24]),
                crc32: 0,
            });
        }
    }
    r
}
