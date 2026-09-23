//! Git pack / index / loose object parsing. No system git is used.

use flate2::Decompress;
use sha1::{Digest, Sha1};
use thiserror::Error;

pub const IDX_MAGIC: [u8; 4] = [0xff, 0x74, 0x4f, 0x63];

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ObjType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        match code {
            1 => Some(ObjType::Commit),
            2 => Some(ObjType::Tree),
            3 => Some(ObjType::Blob),
            4 => Some(ObjType::Tag),
            6 => Some(ObjType::OfsDelta),
            7 => Some(ObjType::RefDelta),
            _ => None,
        }
    }
    pub fn code(self) -> u8 {
        match self {
            ObjType::Commit => 1,
            ObjType::Tree => 2,
            ObjType::Blob => 3,
            ObjType::Tag => 4,
            ObjType::OfsDelta => 6,
            ObjType::RefDelta => 7,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }
    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("bad pack magic")]
    BadMagic,
    #[error("unsupported pack version {0}")]
    BadVersion(u32),
    #[error("truncated at offset {0}")]
    Truncated(u64),
    #[error("unknown object type code {0}")]
    BadType(u8),
    #[error("zlib error: {0}")]
    Zlib(String),
    #[error("declared size {declared} but stream produced {actual} (大小欺骗)")]
    SizeSpoof { declared: u64, actual: u64 },
    #[error("pack checksum mismatch")]
    PackChecksum,
    #[error("bad idx magic")]
    BadIdxMagic,
    #[error("unsupported idx version {0}")]
    BadIdxVersion(u32),
    #[error("not a loose object")]
    NotLoose,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PackEntry {
    pub offset: u64,
    pub otype: ObjType,
    pub declared_size: u64,
    /// Actual inflated size of the zlib stream (found while locating the
    /// stream boundary). Compared against `declared_size` for full objects
    /// to detect size spoofing.
    pub inflated_size: u64,
    /// For ofs-delta: distance back to the base entry.
    pub base_distance: Option<u64>,
    /// For ref-delta: hex oid of the base object.
    pub base_oid: Option<String>,
    /// Offset where the zlib stream starts.
    pub data_start: u64,
    /// Offset just past the end of the zlib stream (zlib boundary).
    pub data_end: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PackFile {
    pub version: u32,
    pub count: u32,
    pub entries: Vec<PackEntry>,
    pub checksum_ok: bool,
    /// Non-fatal parse problem: entries before the failure point are kept.
    pub parse_error: Option<String>,
}

fn be32(buf: &[u8], at: usize) -> Result<u32, ParseError> {
    if at + 4 > buf.len() {
        return Err(ParseError::Truncated(at as u64));
    }
    Ok(u32::from_be_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]]))
}

/// Inflate the zlib stream starting at `start`, returning the decompressed
/// bytes and the offset just past the stream end (zlib boundary detection).
/// The output is capped at `cap` bytes; exceeding the cap reports a size
/// spoof (the stream keeps producing data beyond the declared size).
pub fn inflate_bounded(buf: &[u8], start: u64, cap: u64) -> Result<(Vec<u8>, u64), ParseError> {
    let mut de = Decompress::new(true);
    let mut out: Vec<u8> = Vec::new();
    let input = &buf[start as usize..];
    let mut in_pos = 0usize;
    loop {
        let before_in = de.total_in();
        let before_out = de.total_out();
        let remaining_cap = (cap + 1) as usize - out.len();
        let chunk = remaining_cap.max(1);
        let old_len = out.len();
        out.resize(old_len + chunk, 0u8);
        let res = de
            .decompress(&input[in_pos..], &mut out[old_len..], flate2::FlushDecompress::None)
            .map_err(|e| ParseError::Zlib(e.to_string()))?;
        let produced = (de.total_out() - before_out) as usize;
        out.truncate(old_len + produced);
        in_pos += (de.total_in() - before_in) as usize;
        if out.len() as u64 > cap {
            return Err(ParseError::SizeSpoof {
                declared: cap,
                actual: out.len() as u64,
            });
        }
        match res {
            flate2::Status::StreamEnd => {
                return Ok((out, start + de.total_in()));
            }
            flate2::Status::Ok | flate2::Status::BufError => {
                if in_pos >= input.len() && produced == 0 {
                    return Err(ParseError::Truncated(start));
                }
            }
        }
    }
}

pub fn parse_pack(buf: &[u8]) -> Result<PackFile, ParseError> {
    if buf.len() < 12 || &buf[0..4] != b"PACK" {
        return Err(ParseError::BadMagic);
    }
    let version = be32(buf, 4)?;
    if version != 2 && version != 3 {
        return Err(ParseError::BadVersion(version));
    }
    let count = be32(buf, 8)?;
    let mut entries = Vec::new();
    let mut pos: u64 = 12;
    let mut parse_error = None;
    for _ in 0..count {
        let entry_offset = pos;
        let entry_result = (|| -> Result<PackEntry, ParseError> {
        // Object header: type + size varint.
        let mut byte = *buf.get(pos as usize).ok_or(ParseError::Truncated(pos))?;
        pos += 1;
        let code = (byte >> 4) & 0x7;
        let otype = ObjType::from_code(code).ok_or(ParseError::BadType(code))?;
        let mut size: u64 = (byte & 0x0f) as u64;
        let mut shift = 4u32;
        while byte & 0x80 != 0 {
            byte = *buf.get(pos as usize).ok_or(ParseError::Truncated(pos))?;
            pos += 1;
            size |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
        }
        let mut base_distance = None;
        let mut base_oid = None;
        match otype {
            ObjType::OfsDelta => {
                let mut b = *buf.get(pos as usize).ok_or(ParseError::Truncated(pos))?;
                pos += 1;
                let mut dist: u64 = (b & 0x7f) as u64;
                while b & 0x80 != 0 {
                    b = *buf.get(pos as usize).ok_or(ParseError::Truncated(pos))?;
                    pos += 1;
                    dist = ((dist + 1) << 7) | (b & 0x7f) as u64;
                }
                base_distance = Some(dist);
            }
            ObjType::RefDelta => {
                let end = pos as usize + 20;
                if end > buf.len() {
                    return Err(ParseError::Truncated(pos));
                }
                base_oid = Some(hex::encode(&buf[pos as usize..end]));
                pos = end as u64;
            }
            _ => {}
        }
        let data_start = pos;
        // Scan with a generous cap to locate the zlib boundary; spoofed
        // declared sizes are judged later per-object so one bad object does
        // not abort the whole pack.
        let (probe, data_end) = inflate_bounded(buf, data_start, 1 << 30)?;
        Ok(PackEntry {
            offset: entry_offset,
            otype,
            declared_size,
            inflated_size: probe.len() as u64,
            base_distance,
            base_oid,
            data_start,
            data_end,
        })
        })();
        match entry_result {
            Ok(entry) => {
                pos = entry.data_end;
                entries.push(entry);
            }
            Err(e) => {
                parse_error = Some(format!("entry at offset {}: {}", entry_offset, e));
                break;
            }
        }
    }
    // Pack trailer: sha1 over everything before it.
    let checksum_ok = if buf.len() >= 20 && pos as usize <= buf.len() - 20 {
        let mut h = Sha1::new();
        h.update(&buf[..buf.len() - 20]);
        h.finalize()[..] == buf[buf.len() - 20..]
    } else {
        false
    };
    Ok(PackFile {
        version,
        count,
        entries,
        checksum_ok,
        parse_error,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IdxEntry {
    pub oid: String,
    pub crc32: u32,
    pub offset: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct IdxFile {
    pub fanout: [u32; 256],
    pub entries: Vec<IdxEntry>,
    pub pack_checksum_ok: bool,
}

pub fn parse_idx(buf: &[u8]) -> Result<IdxFile, ParseError> {
    if buf.len() < 8 || buf[0..4] != IDX_MAGIC {
        return Err(ParseError::BadIdxMagic);
    }
    let version = be32(buf, 4)?;
    if version != 2 {
        return Err(ParseError::BadIdxVersion(version));
    }
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = be32(buf, 8 + i * 4)?;
    }
    let n = fanout[255] as usize;
    let oid_base = 8 + 256 * 4;
    let crc_base = oid_base + n * 20;
    let off_base = crc_base + n * 4;
    let big_base = off_base + n * 4;
    if big_base > buf.len() {
        return Err(ParseError::Truncated(buf.len() as u64));
    }
    let mut entries = Vec::with_capacity(n);
    for i in 0..n {
        let oid = hex::encode(&buf[oid_base + i * 20..oid_base + i * 20 + 20]);
        let crc32 = be32(buf, crc_base + i * 4)?;
        let raw = be32(buf, off_base + i * 4)?;
        let offset = if raw & 0x8000_0000 != 0 {
            let idx = (raw & 0x7fff_ffff) as usize;
            let at = big_base + idx * 8;
            if at + 8 > buf.len() {
                return Err(ParseError::Truncated(at as u64));
            }
            u64::from_be_bytes(buf[at..at + 8].try_into().unwrap())
        } else {
            raw as u64
        };
        entries.push(IdxEntry { oid, crc32, offset });
    }
    // idx trailer: pack sha1 then idx sha1 of everything before it.
    let pack_checksum_ok = if buf.len() >= 40 {
        let mut h = Sha1::new();
        h.update(&buf[..buf.len() - 20]);
        h.finalize()[..] == buf[buf.len() - 20..]
    } else {
        false
    };
    Ok(IdxFile {
        fanout,
        entries,
        pack_checksum_ok,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LooseObject {
    pub otype: ObjType,
    pub declared_size: u64,
    pub content: Vec<u8>,
    pub oid: String,
    pub stream_len: u64,
}

pub fn parse_loose(buf: &[u8]) -> Result<LooseObject, ParseError> {
    // Loose objects are zlib streams whose inflated payload starts with
    // "<type> <size>\0". Inflate with a generous cap, then verify the header.
    let (raw, stream_len) = inflate_bounded(buf, 0, 1 << 30)?;
    let nul = raw.iter().position(|&b| b == 0).ok_or(ParseError::NotLoose)?;
    let header = std::str::from_utf8(&raw[..nul]).map_err(|_| ParseError::NotLoose)?;
    let (tname, size_s) = header.split_once(' ').ok_or(ParseError::NotLoose)?;
    let otype = match tname {
        "commit" => ObjType::Commit,
        "tree" => ObjType::Tree,
        "blob" => ObjType::Blob,
        "tag" => ObjType::Tag,
        _ => return Err(ParseError::NotLoose),
    };
    let declared_size: u64 = size_s.parse().map_err(|_| ParseError::NotLoose)?;
    let content = raw[nul + 1..].to_vec();
    if content.len() as u64 != declared_size {
        return Err(ParseError::SizeSpoof {
            declared: declared_size,
            actual: content.len() as u64,
        });
    }
    let oid = git_oid(otype, &content);
    Ok(LooseObject {
        otype,
        declared_size,
        content,
        oid,
        stream_len,
    })
}

/// Compute the git object id: sha1 of "<type> <len>\0" + content.
pub fn git_oid(otype: ObjType, content: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(format!("{} {}\0", otype.name(), content.len()).as_bytes());
    h.update(content);
    hex::encode(h.finalize())
}

/// Detect the kind of an imported file from its bytes.
pub fn detect_kind(buf: &[u8]) -> &'static str {
    if buf.len() >= 4 && &buf[0..4] == b"PACK" {
        "pack"
    } else if buf.len() >= 4 && buf[0..4] == IDX_MAGIC {
        "idx"
    } else {
        "loose"
    }
}
