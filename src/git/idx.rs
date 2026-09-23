use sha1::Digest;
use crate::git::{GitError, ObjType};

#[derive(Clone, Debug)]
pub struct IdxEntry {
    pub oid: [u8; 20],
    pub offset: u64,
    pub crc32: u32,
    pub high_offset: bool,
}

pub struct ParsedIdx {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_sha: [u8; 20],
    pub idx_sha: [u8; 20],
    pub trailer_sha: [u8; 20],
    pub checksum_ok: bool,
}

pub fn parse_idx(data: &[u8]) -> Result<ParsedIdx, GitError> {
    if data.len() < 8 {
        return Err(GitError::new("idx_too_short", "index too short"));
    }
    if &data[0..4] != b"\xfftOc" {
        return Err(GitError::new(
            "idx_v1_unsupported",
            "only v2 index files are supported",
        ));
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(GitError::new("bad_idx_version", format!("idx version {version}")));
    }
    let mut pos = 8usize;
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
    }
    let count = fanout[255] as usize;
    if data.len() < 8 + 1024 + count * (20 + 4 + 4) + 40 {
        return Err(GitError::new("idx_truncated", "index body shorter than fanout claims"));
    }
    let mut oids = Vec::with_capacity(count);
    for _ in 0..count {
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[pos..pos + 20]);
        pos += 20;
        oids.push(oid);
    }
    let mut crcs = Vec::with_capacity(count);
    for _ in 0..count {
        crcs.push(u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap()));
        pos += 4;
    }
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let raw = u32::from_be_bytes(data[pos..pos + 4].try_into().unwrap());
        pos += 4;
        let (offset, high_offset) = if raw & 0x8000_0000 != 0 {
            let table_index = (raw & 0x7fff_ffff) as usize;
            let at = 8 + 1024 + count * 24 + table_index * 8;
            if at + 8 > data.len() - 40 {
                return Err(GitError::new("idx_bad_ofs_table", "64-bit offset table out of range"));
            }
            (u64::from_be_bytes(data[at..at + 8].try_into().unwrap()), true)
        } else {
            (raw as u64, false)
        };
        entries.push(IdxEntry {
            oid: oids[i],
            offset,
            crc32: crcs[i],
            high_offset,
        });
    }

    let mut pack_sha = [0u8; 20];
    let mut idx_sha = [0u8; 20];
    let mut trailer_sha = [0u8; 20];
    pack_sha.copy_from_slice(&data[pos..pos + 20]);
    pos += 20;
    idx_sha.copy_from_slice(&data[pos..pos + 20]);

    let mut h = sha1::Sha1::new();
    sha1::Digest::update(&mut h, &data[..pos]);
    trailer_sha.copy_from_slice(&h.finalize());
    let checksum_ok = idx_sha == trailer_sha && pos + 20 == data.len();

    // Fanout consistency check.
    let mut prev = 0u32;
    for (i, v) in fanout.iter().enumerate() {
        if *v < prev {
            return Err(GitError::new(
                "bad_fanout",
                format!("fanout[{i}] decreased: {prev} -> {v}"),
            ));
        }
        prev = *v;
    }
    for (i, e) in entries.iter().enumerate() {
        let expected = fanout[e.oid[0] as usize] as usize;
        if i >= expected || (i > 0 && entries[i - 1].oid >= e.oid) {
            return Err(GitError::new("bad_fanout", "oid ordering does not match fanout"));
        }
    }

    Ok(ParsedIdx {
        fanout,
        entries,
        pack_sha,
        idx_sha,
        trailer_sha,
        checksum_ok,
    })
}

pub fn type_name(t: ObjType) -> &'static str {
    t.header_name().unwrap_or("delta")
}
