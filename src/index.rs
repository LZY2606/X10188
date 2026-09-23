#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedIndex {
    pub fanout: [u32; 256],
    pub count: u32,
    pub entries: Vec<IdxEntry>,
    pub pack_sha: [u8; 20],
    pub idx_sha: [u8; 20],
    pub idx_checksum_ok: bool,
    pub parse_error: Option<String>,
}

pub fn parse_index(data: &[u8]) -> ParsedIndex {
    let mut p = ParsedIndex {
        fanout: [0u32; 256],
        count: 0,
        entries: Vec::new(),
        pack_sha: [0u8; 20],
        idx_sha: [0u8; 20],
        idx_checksum_ok: false,
        parse_error: None,
    };
    if data.len() < 8 {
        p.parse_error = Some("index too short".into());
        return p;
    }
    // v2 magic: \377tOc + version 2
    if &data[0..4] == b"\xfftOc" {
        let ver = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if ver != 2 {
            p.parse_error = Some(format!("unsupported idx version {}", ver));
            return p;
        }
        let mut off = 8usize;
        if data.len() < off + 256 * 4 {
            p.parse_error = Some("fanout table truncated".into());
            return p;
        }
        for i in 0..256 {
            p.fanout[i] = u32::from_be_bytes(data[off..off + 4].try_into().unwrap());
            off += 4;
        }
        p.count = p.fanout[255];
        let n = p.count as usize;
        let names_off = off;
        let crc_off = names_off + n * 20;
        let off_table = crc_off + n * 4;
        let need = off_table + n * 4 + 40;
        if data.len() < need {
            p.parse_error = Some("idx tables truncated".into());
            return p;
        }
        for i in 0..n {
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[names_off + i * 20..names_off + (i + 1) * 20]);
            let crc = u32::from_be_bytes(
                data[crc_off + i * 4..crc_off + i * 4 + 4].try_into().unwrap(),
            );
            let mut val = u32::from_be_bytes(
                data[off_table + i * 4..off_table + i * 4 + 4].try_into().unwrap(),
            );
            let mut offset = val as u64;
            if val & 0x8000_0000 != 0 {
                val &= 0x7fff_ffff;
                let lo = off_table + n * 4 + val as usize * 8;
                offset = u64::from_be_bytes(data[lo..lo + 8].try_into().unwrap());
            }
            p.entries.push(IdxEntry { oid, offset, crc32: crc });
        }
        p.pack_sha.copy_from_slice(&data[need - 40..need - 20]);
        p.idx_sha.copy_from_slice(&data[need - 20..need]);
        let mut h = crate::gitid::Sha1::new();
        h.update(&data[..need - 20]);
        p.idx_checksum_ok = h.finalize() == p.idx_sha;
    } else {
        // v1: 256 fanout then 25-byte records (4 offset + 20 oid), no CRC table.
        if data.len() < 256 * 4 + 40 {
            p.parse_error = Some("v1 idx too short".into());
            return p;
        }
        for i in 0..256 {
            p.fanout[i] = u32::from_be_bytes(data[i * 4..i * 4 + 4].try_into().unwrap());
        }
        p.count = p.fanout[255];
        let n = p.count as usize;
        let need = 256 * 4 + n * 24 + 40;
        if data.len() < need {
            p.parse_error = Some("v1 idx records truncated".into());
            return p;
        }
        for i in 0..n {
            let base = 256 * 4 + i * 24;
            let offset = u32::from_be_bytes(data[base..base + 4].try_into().unwrap()) as u64;
            let mut oid = [0u8; 20];
            oid.copy_from_slice(&data[base + 4..base + 24]);
            p.entries.push(IdxEntry { oid, offset, crc32: 0 });
        }
        p.pack_sha.copy_from_slice(&data[need - 40..need - 20]);
        p.idx_sha.copy_from_slice(&data[need - 20..need]);
        let mut h = crate::gitid::Sha1::new();
        h.update(&data[..need - 20]);
        p.idx_checksum_ok = h.finalize() == p.idx_sha;
    }
    p
}
