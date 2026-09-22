use sha1::Digest;
use crate::git::ObjectId;

#[derive(Debug, Clone)]
pub struct IdxEntry {
    pub oid: ObjectId,
    pub offset: u64,
    pub crc32: u32,
}

#[derive(Debug, Clone)]
pub struct IdxParse {
    pub version: u32,
    pub object_count: u32,
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub checksum_ok: bool,
    pub pack_checksum_ok: bool,
    pub errors: Vec<String>,
}

pub fn parse_idx(data: &[u8], pack: Option<&[u8]>) -> Result<IdxParse, String> {
    if data.len() < 8 { return Err("index too short".into()); }
    let (version, object_count_offset) = if &data[..4] == b"\xfftOc" {
        let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
        if version != 2 { return Err(format!("unsupported idx version {version}")); }
        (version, 8usize)
    } else {
        (1u32, 0usize)
    };

    let fanout_start = object_count_offset;
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32::from_be_bytes(data[fanout_start+i*4..fanout_start+(i+1)*4].try_into().map_err(|_| "bad fanout table")?);
    }
    let object_count = fanout[255];
    let mut errors = Vec::new();
    for window in fanout.windows(2) {
        if window[0] > window[1] { errors.push("fanout table is not monotonic".into()); break; }
    }

    let n = object_count as usize;
    let oid_start = fanout_start + 1024;
    let crc_start = oid_start + n.checked_mul(20).ok_or("object count overflow")?;
    let offset_start = crc_start + n.checked_mul(4).ok_or("object count overflow")?;
    let large_offset_start = offset_start + n.checked_mul(4).ok_or("object count overflow")?;
    let required_end_v2 = large_offset_start + 40;
    let required_end_v1 = fanout_start + n * 24 + 20;
    let required_end = if version == 2 { required_end_v2 } else { required_end_v1 };
    if data.len() < required_end { return Err("index tables truncated".into()); }

    let mut entries = Vec::with_capacity(n);
    let mut previous: Option<ObjectId> = None;
    for i in 0..n {
        let oid = if version == 2 {
            ObjectId::new(data[oid_start+i*20..oid_start+(i+1)*20].try_into().unwrap())
        } else {
            ObjectId::new(data[fanout_start+i*24..fanout_start+i*24+20].try_into().unwrap())
        };
        if let Some(previous) = previous {
            if oid <= previous { errors.push(format!("oid table not strictly sorted at {i}")); break; }
        }
        previous = Some(oid);
        let crc32 = if version == 2 {
            u32::from_be_bytes(data[crc_start+i*4..crc_start+(i+1)*4].try_into().unwrap())
        } else { 0 };
        let raw_offset = if version == 2 {
            u32::from_be_bytes(data[offset_start+i*4..offset_start+(i+1)*4].try_into().unwrap())
        } else {
            u32::from_be_bytes(data[fanout_start+i*24+20..fanout_start+i*24+24].try_into().unwrap())
        };
        let offset = if version == 2 && raw_offset & 0x8000_0000 != 0 {
            let table_index = (raw_offset & 0x7fff_ffff) as usize;
            let pos = large_offset_start + table_index.checked_mul(8).ok_or("large offset overflow")?;
            u64::from_be_bytes(data.get(pos..pos+8).ok_or("large offset table truncated")?.try_into().unwrap())
        } else { raw_offset as u64 };
        entries.push(IdxEntry { oid, offset, crc32 });
    }

    let idx_checksum = ObjectId::new(data[data.len()-20..].try_into().unwrap());
    let mut hasher = sha1::Sha1::new();
    sha1::Digest::update(&mut hasher, &data[..data.len()-20]);
    let checksum_ok = ObjectId::new(sha1::Digest::finalize(hasher).into()) == idx_checksum;
    if !checksum_ok { errors.push(format!("index SHA1 mismatch: stored {idx_checksum}")); }

    let mut pack_checksum_ok = true;
    if let Some(pack) = pack {
        if pack.len() >= 20 {
            let expected = ObjectId::new(pack[pack.len()-20..].try_into().unwrap());
            let stored = ObjectId::new(data[data.len()-40..data.len()-20].try_into().unwrap());
            pack_checksum_ok = expected == stored;
            if !pack_checksum_ok { errors.push(format!("index pack checksum {stored} does not match imported pack {expected}")); }
        }
    }
    Ok(IdxParse { version, object_count, fanout, entries, checksum_ok, pack_checksum_ok, errors })
}
