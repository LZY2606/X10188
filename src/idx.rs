#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid_hex: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone)]
pub struct IdxParse {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum_hex: String,
    pub idx_checksum_hex: String,
    pub computed_idx_checksum_hex: String,
    pub total: u32,
}

pub fn parse_idx(data: &[u8]) -> Result<IdxParse, String> {
    if data.len() < 8 {
        return Err("index too short".into());
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().unwrap());
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if magic != 0xff744f63 {
        return Err("only pack-index v2 is supported (missing \\377tOc magic)".into());
    }
    if version != 2 {
        return Err(format!("unsupported idx version {}", version));
    }
    if data.len() < 8 + 1024 {
        return Err("fanout table truncated".into());
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        let s = 8 + i * 4;
        fanout[i] = u32::from_be_bytes(data[s..s + 4].try_into().unwrap());
    }
    let total = fanout[255];
    let n = total as usize;
    let mut need = 8 + 1024 + n * 20 + n * 4 + n * 4 + 20 + 20;
    if data.len() < need {
        return Err("idx tables truncated".into());
    }
    let oid_base = 8 + 1024;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let large_base = off_base + n * 4;

    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid_hex = crate::hexutil::to_hex(&data[oid_base + i * 20..oid_base + i * 20 + 20]);
        let crc32 =
            u32::from_be_bytes(data[crc_base + i * 4..crc_base + i * 4 + 4].try_into().unwrap());
        let off_raw = u32::from_be_bytes(
            data[off_base + i * 4..off_base + i * 4 + 4].try_into().unwrap(),
        );
        let offset = if off_raw & 0x8000_0000 != 0 {
            let li = (off_raw & 0x7fff_ffff) as usize;
            let s = large_base + li * 8;
            u64::from_be_bytes(data[s..s + 8].try_into().unwrap())
        } else {
            off_raw as u64
        };
        entries.push(IdxEntry {
            oid_hex,
            crc32,
            offset,
        });
    }

    let pack_ck_pos = large_base;
    let idx_ck_pos = pack_ck_pos + 20;
    let pack_checksum_hex = crate::hexutil::to_hex(&data[pack_ck_pos..pack_ck_pos + 20]);
    let idx_checksum_hex = crate::hexutil::to_hex(&data[idx_ck_pos..idx_ck_pos + 20]);
    let computed_idx_checksum_hex = crate::gitobj::sha1_hex(&data[..idx_ck_pos]);
    let _ = &mut need;

    Ok(IdxParse {
        fanout,
        entries,
        pack_checksum_hex,
        idx_checksum_hex,
        computed_idx_checksum_hex,
        total,
    })
}
