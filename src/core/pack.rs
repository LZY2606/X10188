// PACK v2 parser: header scan, zlib boundaries, CRC and pack checksum.

use super::git::{read_entry_head, read_ofs_distance, EntryType};

#[derive(Clone, Debug)]
pub enum StreamError {
    Zlib(String),
    SizeMismatch { declared: u64, actual: u64 },
    SizeSpoof { declared: u64 },
}

impl StreamError {
    pub fn label(&self) -> &'static str {
        match self {
            StreamError::Zlib(_) => "zlib",
            StreamError::SizeMismatch { .. } => "size-mismatch",
            StreamError::SizeSpoof { .. } => "size-spoof",
        }
    }
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::Zlib(s) => write!(f, "{s}"),
            StreamError::SizeMismatch { declared, actual } => write!(
                f,
                "declared inflated size {declared} but stream produced {actual} bytes"
            ),
            StreamError::SizeSpoof { declared } => write!(
                f,
                "stream exceeded declared size {declared} (size spoof detected mid-inflate)"
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct PackEntry {
    pub index: usize,
    /// Absolute offset of the entry header in the pack file.
    pub offset: u64,
    /// Absolute offset where the zlib stream begins.
    pub data_offset: u64,
    /// Absolute offset just past the zlib stream.
    pub end_offset: u64,
    pub etype: EntryType,
    pub declared_size: u64,
    pub ofs_distance: Option<u64>,
    pub base_oid: Option<[u8; 20]>,
    /// CRC32 over the compressed bytes (indexable against an .idx).
    pub crc32: Option<u32>,
    /// Inflated bytes: object content for bases, delta payload for deltas.
    pub inflated: Result<Vec<u8>, StreamError>,
}

#[derive(Clone, Debug)]
pub struct ParsedPack {
    pub version: u32,
    pub num_entries: u32,
    pub entries: Vec<PackEntry>,
    pub trailer_sha: [u8; 20],
    pub computed_sha: [u8; 20],
    pub checksum_ok: bool,
    /// Fatal scanner failure (entries after this point are unreachable).
    pub scan_error: Option<String>,
}

const MAGIC: &[u8; 4] = b"PACK";

pub fn parse_pack(buf: &[u8]) -> Result<ParsedPack, String> {
    if buf.len() < 32 {
        return Err("file shorter than pack header+trailer".into());
    }
    if &buf[0..4] != MAGIC {
        return Err("bad pack magic".into());
    }
    let version = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    if version != 2 {
        return Err(format!("unsupported pack version {version}"));
    }
    let num_entries = u32::from_be_bytes(buf[8..12].try_into().unwrap());

    let mut entries: Vec<PackEntry> = Vec::new();
    let mut pos = 12usize;
    let mut scan_error: Option<String> = None;

    for index in 0..num_entries as usize {
        let entry_offset = pos;
        if pos + 2 > buf.len() - 20 {
            scan_error = Some(format!("entry {index}: header runs past pack body"));
            break;
        }
        let (etype, declared, head_end) = match read_entry_head(buf, pos) {
            Ok(v) => v,
            Err(e) => {
                scan_error = Some(format!("entry {index} at offset {pos}: {e}"));
                break;
            }
        };
        let mut p = head_end;
        let mut ofs_distance = None;
        let mut base_oid = None;
        match etype {
            EntryType::OfsDelta => match read_ofs_distance(buf, p) {
                Ok((d, np)) => {
                    ofs_distance = Some(d);
                    p = np;
                }
                Err(e) => {
                    scan_error = Some(format!("entry {index} ofs distance: {e}"));
                    break;
                }
            },
            EntryType::RefDelta => {
                if p + 20 > buf.len() - 20 {
                    scan_error = Some(format!("entry {index}: ref base oid truncated"));
                    break;
                }
                let mut oid = [0u8; 20];
                oid.copy_from_slice(&buf[p..p + 20]);
                base_oid = Some(oid);
                p += 20;
            }
            EntryType::Base(_) => {}
        }
        let data_offset = p;
        match super::inflate::inflate_stream(buf, data_offset, declared) {
            Ok(r) => {
                let crc = crc32fast::hash(&buf[data_offset..data_offset + r.consumed]);
                let end = data_offset + r.consumed;
                entries.push(PackEntry {
                    index,
                    offset: entry_offset as u64,
                    data_offset: data_offset as u64,
                    end_offset: end as u64,
                    etype,
                    declared_size: declared,
                    ofs_distance,
                    base_oid,
                    crc32: Some(crc),
                    inflated: Ok(r.data),
                });
                pos = end;
            }
            Err(e) => {
                let se = match e {
                    super::inflate::InflateError::ZlibError(s) => StreamError::Zlib(s),
                    super::inflate::InflateError::SizeMismatch { declared, actual } => {
                        StreamError::SizeMismatch { declared, actual }
                    }
                    super::inflate::InflateError::SizeSpoof { declared } => {
                        StreamError::SizeSpoof { declared }
                    }
                };
                entries.push(PackEntry {
                    index,
                    offset: entry_offset as u64,
                    data_offset: data_offset as u64,
                    end_offset: data_offset as u64,
                    etype,
                    declared_size: declared,
                    ofs_distance,
                    base_oid,
                    crc32: None,
                    inflated: Err(se),
                });
                scan_error = Some(format!(
                    "entry {index} at offset {entry_offset}: failed to inflate; subsequent entries cannot be located"
                ));
                break;
            }
        }
    }

    let computed_sha = {
        use sha1::{Digest, Sha1};
        let body_len = buf.len().saturating_sub(20);
        Sha1::digest(&buf[..body_len]).into()
    };
    let mut trailer_sha = [0u8; 20];
    trailer_sha.copy_from_slice(&buf[buf.len() - 20..]);
    let checksum_ok = trailer_sha == computed_sha;

    Ok(ParsedPack {
        version,
        num_entries,
        entries,
        trailer_sha,
        computed_sha,
        checksum_ok,
        scan_error,
    })
}
