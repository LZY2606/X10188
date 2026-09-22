// PACK index (.idx) parsers for version 1 and version 2, including fanout.

#[derive(Clone, Debug)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc32: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct ParsedIdx {
    pub version: u8,
    pub fanout: [u32; 256],
    pub num_entries: u32,
    pub entries: Vec<IdxEntry>,
    /// Offsets that point at the 8-byte extended-offset table (64 bit table).
    pub pack_checksum: [u8; 20],
    pub idx_checksum: [u8; 20],
    pub computed_idx_sha: [u8; 20],
    pub idx_checksum_ok: bool,
    pub parse_error: Option<String>,
}

const V2_MAGIC: &[u8; 4] = &[255, 116, 79, 99]; // \377tOc

pub fn parse_idx(buf: &[u8]) -> Result<ParsedIdx, String> {
    if buf.len() < 8 + 256 * 4 {
        return Err("idx shorter than fanout table".into());
    }
    if &buf[0..4] == V2_MAGIC {
        parse_v2(buf)
    } else {
        parse_v1(buf)
    }
}

fn read_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
}

fn fanout(buf: &[u8], base: usize) -> [u32; 256] {
    let mut f = [0u32; 256];
    for (i, slot) in f.iter_mut().enumerate() {
        *slot = read_u32(buf, base + i * 4);
    }
    f
}

fn parse_v2(buf: &[u8]) -> Result<ParsedIdx, String> {
    let version = read_u32(buf, 4);
    if version != 2 {
        return Err(format!("unsupported idx v2 version field {version}"));
    }
    let fan = fanout(buf, 8);
    let n = fan[255] as usize;

    let mut p = 8 + 256 * 4;
    let need_oids = p + n * 20;
    let need_crc = need_oids + n * 4;
    let need_off = need_crc + n * 4;
    if buf.len() < need_off + 40 {
        return Err("idx v2 tables truncated".into());
    }

    let mut oids = Vec::with_capacity(n);
    for _ in 0..n {
        let mut o = [0u8; 20];
        o.copy_from_slice(&buf[p..p + 20]);
        oids.push(o);
        p += 20;
    }
    let crc_base = p;
    p = need_oids;
    let mut crcs = Vec::with_capacity(n);
    for i in 0..n {
        crcs.push(read_u32(buf, crc_base + i * 4));
    }
    let off_base = need_crc;
    // Locate the 8-byte offset table position (immediately after 4-byte table).
    let mut extended: Vec<u64> = Vec::new();
    let large_off = need_off;
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let raw = read_u32(buf, off_base + i * 4);
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            let at = large_off + idx * 8;
            if at + 8 > buf.len() - 40 {
                return Err("extended offset index out of range".into());
            }
            let v = u64::from_be_bytes(buf[at..at + 8].try_into().unwrap());
            extended.push(v);
            v
        } else {
            raw as u64
        };
        entries.push(IdxEntry {
            oid: oids[i],
            offset,
            crc32: Some(crcs[i]),
        });
    }
    let _ = extended;

    // Trailer: 20-byte pack checksum then 20-byte idx checksum.
    // They sit at the very end, after the (possibly present) large-offset table.
    let idx_sha_pos = buf.len() - 20;
    let pack_sha_pos = idx_sha_pos - 20;
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&buf[pack_sha_pos..idx_sha_pos]);
    let mut idx_checksum = [0u8; 20];
    idx_checksum.copy_from_slice(&buf[idx_sha_pos..]);
    let computed: [u8; 20] = {
        use sha1::{Digest, Sha1};
        Sha1::digest(&buf[..pack_sha_pos]).into()
    };
    let idx_checksum_ok = computed == idx_checksum;

    Ok(ParsedIdx {
        version: 2,
        fanout: fan,
        num_entries: n as u32,
        entries,
        pack_checksum,
        idx_checksum,
        computed_idx_sha: computed,
        idx_checksum_ok,
        parse_error: None,
    })
}

fn parse_v1(buf: &[u8]) -> Result<ParsedIdx, String> {
    if buf.len() < 256 * 4 + 40 {
        return Err("idx v1 too short".into());
    }
    let fan = fanout(buf, 0);
    let n = fan[255] as usize;
    let mut p = 256 * 4;
    if buf.len() < p + n * 24 + 40 {
        return Err("idx v1 entries truncated".into());
    }
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let offset = read_u32(buf, p) as u64;
        p += 4;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&buf[p..p + 20]);
        p += 20;
        entries.push(IdxEntry {
            oid,
            offset,
            crc32: None,
        });
    }
    let idx_sha_pos = buf.len() - 20;
    let pack_sha_pos = idx_sha_pos - 20;
    let mut pack_checksum = [0u8; 20];
    pack_checksum.copy_from_slice(&buf[pack_sha_pos..idx_sha_pos]);
    let mut idx_checksum = [0u8; 20];
    idx_checksum.copy_from_slice(&buf[idx_sha_pos..]);
    let computed: [u8; 20] = {
        use sha1::{Digest, Sha1};
        Sha1::digest(&buf[..pack_sha_pos]).into()
    };

    Ok(ParsedIdx {
        version: 1,
        fanout: fan,
        num_entries: n as u32,
        entries,
        pack_checksum,
        idx_checksum,
        computed_idx_sha: computed,
        idx_checksum_ok: computed == idx_checksum,
        parse_error: None,
    })
}
