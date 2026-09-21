use flate2::{Decompress, FlushDecompress, Status};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum ObjType {
    Commit = 1,
    Tree = 2,
    Blob = 3,
    Tag = 4,
    OfsDelta = 6,
    RefDelta = 7,
}

impl ObjType {
    pub fn from_code(code: u8) -> Option<ObjType> {
        Some(match code {
            1 => ObjType::Commit,
            2 => ObjType::Tree,
            3 => ObjType::Blob,
            4 => ObjType::Tag,
            6 => ObjType::OfsDelta,
            7 => ObjType::RefDelta,
            _ => return None,
        })
    }
    pub fn base_type(self) -> Option<&'static str> {
        Some(match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            _ => return None,
        })
    }
    pub fn type_name(self) -> &'static str {
        match self {
            ObjType::Commit => "commit",
            ObjType::Tree => "tree",
            ObjType::Blob => "blob",
            ObjType::Tag => "tag",
            ObjType::OfsDelta => "ofs-delta",
            ObjType::RefDelta => "ref-delta",
        }
    }
    pub fn named(s: &str) -> Option<ObjType> {
        Some(match s {
            "commit" => ObjType::Commit,
            "tree" => ObjType::Tree,
            "blob" => ObjType::Blob,
            "tag" => ObjType::Tag,
            "ofs-delta" => ObjType::OfsDelta,
            "ref-delta" => ObjType::RefDelta,
            _ => return None,
        })
    }
    pub fn is_delta(self) -> bool {
        matches!(self, ObjType::OfsDelta | ObjType::RefDelta)
    }
}

impl fmt::Display for ObjType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.type_name())
    }
}

#[derive(Debug)]
pub enum ParseError {
    Truncated,
    BadType(u8),
}

pub fn read_size_varint(data: &[u8], mut pos: usize) -> Result<(u64, usize), ParseError> {
    let first = *data.get(pos).ok_or(ParseError::Truncated)?;
    let mut size = (first & 0x0f) as u64;
    let mut shift = 4;
    pos += 1;
    let mut cur = first;
    while cur & 0x80 != 0 {
        cur = *data.get(pos).ok_or(ParseError::Truncated)?;
        pos += 1;
        size |= ((cur & 0x7f) as u64) << shift;
        shift += 7;
    }
    Ok((size, pos))
}

pub fn read_delta_varint(data: &[u8], mut pos: usize) -> Result<(u64, usize), ParseError> {
    let mut shift = 0u32;
    let mut size = 0u64;
    loop {
        let cur = *data.get(pos).ok_or(ParseError::Truncated)?;
        pos += 1;
        size |= ((cur & 0x7f) as u64) << shift;
        if cur & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(ParseError::BadType(0));
        }
    }
    Ok((size, pos))
}

pub fn read_ofs_distance(data: &[u8], mut pos: usize) -> Result<(u64, usize), ParseError> {
    let first = *data.get(pos).ok_or(ParseError::Truncated)?;
    let mut ofs = (first & 0x7f) as u64;
    pos += 1;
    let mut cur = first;
    while cur & 0x80 != 0 {
        cur = *data.get(pos).ok_or(ParseError::Truncated)?;
        pos += 1;
        ofs = ofs.wrapping_add(1).wrapping_shl(7) | (cur & 0x7f) as u64;
    }
    Ok((ofs, pos))
}

pub fn parse_entry_header(data: &[u8], pos: usize) -> Result<(ObjType, u64, usize), ParseError> {
    let first = *data.get(pos).ok_or(ParseError::Truncated)?;
    let code = first >> 4 & 7;
    let typ = ObjType::from_code(code).ok_or(ParseError::BadType(code))?;
    let (size, next) = read_size_varint(data, pos)?;
    Ok((typ, size, next))
}

pub fn git_object_id(type_name: &str, content: &[u8]) -> [u8; 20] {
    use sha1::{Digest, Sha1};
    let mut h = Sha1::new();
    h.update(type_name.as_bytes());
    h.update(b" ");
    h.update(content.len().to_string().as_bytes());
    h.update(b"\0");
    h.update(content);
    h.finalize().into()
}

#[derive(Clone, Debug)]
pub struct InflateOutcome {
    pub data: Vec<u8>,
    pub consumed: usize,
    pub trailing: bool,
}

#[derive(Debug)]
pub enum InflateError {
    Truncated,
    Corrupt(String),
    SizeSpoof { declared: u64, actual: u64 },
    TooLarge { declared: Option<u64>, limit: u64 },
}

pub fn bounded_inflate(
    input: &[u8],
    declared_size: Option<u64>,
    hard_limit: u64,
) -> Result<InflateOutcome, InflateError> {
    let mut dec = Decompress::new(true);
    let limit = match declared_size {
        Some(d) => (d.saturating_add(1)).min(hard_limit),
        None => hard_limit,
    };
    let cap = (limit.min(1 << 20)) as usize;
    let mut out: Vec<u8> = Vec::with_capacity(cap);
    let mut in_pos = 0usize;
    loop {
        if out.len() as u64 >= limit {
            if declared_size.is_some() {
                return Err(InflateError::SizeSpoof {
                    declared: declared_size.unwrap(),
                    actual: out.len() as u64,
                });
            }
            return Err(InflateError::TooLarge {
                declared: None,
                limit,
            });
        }
        let want = 64 * 1024;
        let old_len = out.len();
        out.resize(old_len + want, 0);
        let before_in = in_pos;
        let before_out = dec.total_out();
        let status = dec
            .decompress(
                &input[in_pos..],
                &mut out[old_len..],
                FlushDecompress::None,
            )
            .map_err(|e| InflateError::Corrupt(e.to_string()))?;
        in_pos += (dec.total_in() - (before_in as u64)) as usize;
        let produced = (dec.total_out() - before_out) as usize;
        out.truncate(old_len + produced);
        match status {
            Status::StreamEnd => {
                break;
            }
            Status::Ok => {
                if in_pos == input.len() {
                    return Err(InflateError::Truncated);
                }
            }
            Status::BufError => {
                if in_pos == before_in && produced == 0 {
                    if in_pos == input.len() {
                        return Err(InflateError::Truncated);
                    }
                }
            }
        }
    }
    if let Some(d) = declared_size {
        if out.len() as u64 != d {
            return Err(InflateError::SizeSpoof {
                declared: d,
                actual: out.len() as u64,
            });
        }
    }
    let trailing = in_pos < input.len();
    Ok(InflateOutcome {
        data: out,
        consumed: in_pos,
        trailing,
    })
}

pub fn oid_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}
