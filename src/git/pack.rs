use sha1::Digest;
use crate::git::object_id;
use crate::git::varint::{read_entry_header, read_ofs_distance};
use crate::git::zdec::{inflate_one, ZlibRange};
use crate::git::{GitError, ObjType};

#[derive(Clone, Debug)]
pub struct PackEntry {
    pub ordinal: usize,
    pub obj_type: ObjType,
    pub declared_size: u64,
    pub header_start: usize,
    pub header_end: usize,
    pub zlib: Option<ZlibRange>,
    pub ofs_base_offset: Option<u64>,
    pub ref_base_oid: Option<[u8; 20]>,
    pub inflated: Option<Vec<u8>>,
    pub inflate_error: Option<String>,
    pub crc_from_index: Option<u32>,
    pub crc_actual: Option<u32>,
    pub crc_ok: Option<bool>,
}

pub struct ParsedPack {
    pub entries: Vec<PackEntry>,
    pub object_count: u32,
    pub pack_sha: [u8; 20],
    pub trailer_sha: [u8; 20],
    pub checksum_ok: bool,
    pub parse_errors: Vec<(usize, String)>,
}

const MAGIC: &[u8; 4] = b"PACK";

pub fn parse_pack(data: &[u8], hard_cap: usize) -> Result<ParsedPack, GitError> {
    if data.len() < 32 {
        return Err(GitError::new("pack_too_short", "pack shorter than 32 bytes"));
    }
    if &data[0..4] != MAGIC {
        return Err(GitError::new("bad_magic", "missing PACK magic"));
    }
    let version = u32::from_be_bytes(data[4..8].try_into().unwrap());
    if version != 2 {
        return Err(GitError::new("bad_version", format!("unsupported pack version {version}")));
    }
    let object_count = u32::from_be_bytes(data[8..12].try_into().unwrap());
    let mut entries: Vec<PackEntry> = Vec::new();
    let mut parse_errors: Vec<(usize, String)> = Vec::new();
    let mut pos = 12usize;

    for ordinal in 0..object_count as usize {
        let header_start = pos;
        match parse_entry(data, &mut pos, ordinal, hard_cap) {
            Ok(e) => entries.push(e),
            Err(e) => {
                parse_errors.push((ordinal, e.clone()));
                break;
            }
        }
        let _ = header_start;
    }

    let trailer_off = pos;
    let mut pack_sha = [0u8; 20];
    let mut hasher = sha1::Sha1::new();
    sha1::Digest::update(&mut hasher, &data[..trailer_off]);
    pack_sha.copy_from_slice(&hasher.finalize());
    let mut trailer_sha = [0u8; 20];
    if trailer_off + 20 <= data.len() {
        trailer_sha.copy_from_slice(&data[trailer_off..trailer_off + 20]);
    } else {
        parse_errors.push((usize::MAX, "pack missing 20-byte checksum trailer".into()));
    }
    let checksum_ok = pack_sha == trailer_sha && trailer_off + 20 == data.len();
    if !checksum_ok {
        parse_errors.push((usize::MAX, "pack SHA1 trailer mismatch".into()));
    }

    Ok(ParsedPack {
        entries,
        object_count,
        pack_sha,
        trailer_sha,
        checksum_ok,
        parse_errors,
    })
}

fn parse_entry(
    data: &[u8],
    pos: &mut usize,
    ordinal: usize,
    hard_cap: usize,
) -> Result<PackEntry, String> {
    let header_start = *pos;
    let (type_code, declared_size, after_word) = read_entry_header(data, header_start)?;
    let obj_type = ObjType::from_pack_code(type_code)
        .ok_or_else(|| format!("invalid object type code {type_code}"))?;
    let mut p = after_word;
    let mut ofs_base_offset = None;
    let mut ref_base_oid = None;
    if obj_type == ObjType::OfsDelta {
        let (dist, np) = read_ofs_distance(data, p)?;
        p = np;
        if dist > header_start as u64 {
            return Err(format!(
                "ofs-delta distance {dist} points before pack start at offset {header_start}"
            ));
        }
        ofs_base_offset = Some(header_start as u64 - dist);
    } else if obj_type == ObjType::RefDelta {
        if p + 20 > data.len() {
            return Err("ref-delta base oid truncated".into());
        }
        let mut oid = [0u8; 20];
        oid.copy_from_slice(&data[p..p + 20]);
        p += 20;
        ref_base_oid = Some(oid);
    }
    let header_end = p;
    let (inflated, zlib, inflate_error) = match inflate_one(data, p, declared_size, hard_cap) {
        Ok((out, range)) => (Some(out), Some(range), None),
        Err(e) => (None, None, Some(e)),
    };
    if let Some(z) = &zlib {
        *pos = z.compressed_end;
    }
    Ok(PackEntry {
        ordinal,
        obj_type,
        declared_size,
        header_start,
        header_end,
        zlib,
        ofs_base_offset,
        ref_base_oid,
        inflated,
        inflate_error,
        crc_from_index: None,
        crc_actual: None,
        crc_ok: None,
    })
}

impl ParsedPack {
    pub fn entry_by_offset(&self, offset: u64) -> Option<&PackEntry> {
        self.entries
            .iter()
            .find(|e| e.header_start as u64 == offset)
    }

    pub fn compute_crcs(&mut self, data: &[u8]) {
        for e in self.entries.iter_mut() {
            if let Some(z) = &e.zlib {
                e.crc_actual =
                    Some(object_id::crc32_zlib_bytes(&data[z.compressed_start..z.compressed_end]));
            }
            if let (Some(expected), Some(actual)) = (e.crc_from_index, e.crc_actual) {
                e.crc_ok = Some(expected == actual);
            }
        }
    }
}
