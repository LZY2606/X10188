use crate::oid::{self, Oid};
use crate::zutil::inflate_bounded;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EntryKind {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl EntryKind {
    pub fn from_code(code: u8) -> Option<EntryKind> {
        Some(match code {
            1 => EntryKind::Commit,
            2 => EntryKind::Tree,
            3 => EntryKind::Blob,
            4 => EntryKind::Tag,
            6 => EntryKind::OfsDelta,
            7 => EntryKind::RefDelta,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            EntryKind::Commit => "commit",
            EntryKind::Tree => "tree",
            EntryKind::Blob => "blob",
            EntryKind::Tag => "tag",
            EntryKind::OfsDelta => "ofs_delta",
            EntryKind::RefDelta => "ref_delta",
        }
    }

    pub fn is_delta(self) -> bool {
        matches!(self, EntryKind::OfsDelta | EntryKind::RefDelta)
    }
}

#[derive(Clone, Debug)]
pub struct RawEntry {
    pub index: usize,
    pub offset: u64,
    pub kind: EntryKind,
    pub declared_size: u64,
    pub header_len: u64,
    pub ofs_dist: Option<u64>,
    pub base_offset: Option<u64>,
    pub base_oid: Option<Oid>,
    pub data_start: u64,
    pub data_len: u64,
    pub end_offset: u64,
    pub inflated_size: u64,
    pub size_ok: bool,
    pub crc32: u32,
}

pub struct ParsedPack {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<RawEntry>,
    pub trailer_ok: bool,
    pub parse_error: Option<String>,
}

fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut c = flate2::Crc::new();
    c.update(data);
    c.sum()
}

pub fn parse_pack(bytes: &[u8]) -> Result<ParsedPack, String> {
    if bytes.len() < 12 {
        return Err("pack shorter than header".to_string());
    }
    if &bytes[0..4] != b"PACK" {
        return Err("bad pack magic".to_string());
    }
    let version = be32(&bytes[4..8]);
    let count = be32(&bytes[8..12]);
    if version != 2 && version != 3 {
        return Err(format!("unsupported pack version {version}"));
    }

    let mut entries = Vec::new();
    let mut pos = 12usize;
    let mut parse_error: Option<String> = None;

    for idx in 0..count as usize {
        let entry_offset = pos as u64;
        let header_start = pos;
        let mut byte = match bytes.get(pos) {
            Some(b) => *b,
            None => {
                parse_error = Some(format!("entry {idx}: EOF in type/size header"));
                break;
            }
        };
        pos += 1;
        let code = (byte >> 4) & 0x7;
        let kind = match EntryKind::from_code(code) {
            Some(k) => k,
            None => {
                parse_error = Some(format!("entry {idx}: bad object type code {code}"));
                break;
            }
        };
        let mut size = (byte & 0x0f) as u64;
        let mut shift = 4u32;
        while byte & 0x80 != 0 {
            byte = match bytes.get(pos) {
                Some(b) => *b,
                None => {
                    parse_error = Some(format!("entry {idx}: EOF in size varint"));
                    break;
                }
            };
            pos += 1;
            size |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            if shift > 63 {
                parse_error = Some(format!("entry {idx}: size varint too long"));
                break;
            }
        }
        if parse_error.is_some() {
            break;
        }

        let mut ofs_dist = None;
        let mut base_offset = None;
        let mut base_oid = None;
        match kind {
            EntryKind::OfsDelta => {
                let mut b = match bytes.get(pos) {
                    Some(b) => *b,
                    None => {
                        parse_error = Some(format!("entry {idx}: EOF in ofs-delta header"));
                        break;
                    }
                };
                pos += 1;
                let mut dist = (b & 0x7f) as u64;
                while b & 0x80 != 0 {
                    b = match bytes.get(pos) {
                        Some(b) => *b,
                        None => {
                            parse_error = Some(format!("entry {idx}: EOF in ofs-delta header"));
                            break;
                        }
                    };
                    pos += 1;
                    dist = ((dist + 1) << 7) | (b & 0x7f) as u64;
                }
                ofs_dist = Some(dist);
                base_offset = entry_offset.checked_sub(dist);
            }
            EntryKind::RefDelta => {
                if pos + 20 > bytes.len() {
                    parse_error = Some(format!("entry {idx}: EOF in ref-delta base oid"));
                    break;
                }
                let mut oid = [0u8; 20];
                oid.copy_from_slice(&bytes[pos..pos + 20]);
                pos += 20;
                base_oid = Some(oid);
            }
            _ => {}
        }
        if parse_error.is_some() {
            break;
        }

        let header_len = (pos as u64) - entry_offset;
        let data_start = pos as u64;
        match inflate_bounded(&bytes[pos..]) {
            Ok(inf) => {
                let end = pos + inf.consumed;
                let crc = crc32(&bytes[header_start..end]);
                entries.push(RawEntry {
                    index: idx,
                    offset: entry_offset,
                    kind,
                    declared_size: size,
                    header_len,
                    ofs_dist,
                    base_offset,
                    base_oid,
                    data_start,
                    data_len: inf.consumed as u64,
                    end_offset: end as u64,
                    inflated_size: inf.data.len() as u64,
                    size_ok: inf.data.len() as u64 == size,
                    crc32: crc,
                });
                pos = end;
            }
            Err(e) => {
                parse_error = Some(format!("entry {idx} @ {entry_offset}: zlib: {e}"));
                break;
            }
        }
    }

    let trailer_ok = bytes.len() >= 20
        && &bytes[bytes.len() - 20..] == &oid::sha1_raw(&bytes[..bytes.len() - 20]);

    Ok(ParsedPack {
        version,
        count,
        entries,
        trailer_ok,
        parse_error,
    })
}
