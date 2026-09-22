use flate2::{write::ZlibEncoder, Compression, Decompress, FlushDecompress};
use sha1::{Digest, Sha1};
use std::io::Write;

pub type Oid = [u8; 20];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
    OfsDelta,
    RefDelta,
    Unknown(u8),
}

impl ObjectType {
    pub fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Commit,
            2 => Self::Tree,
            3 => Self::Blob,
            4 => Self::Tag,
            6 => Self::OfsDelta,
            7 => Self::RefDelta,
            other => Self::Unknown(other),
        }
    }

    pub fn code(self) -> Option<u8> {
        match self {
            Self::Commit => Some(1),
            Self::Tree => Some(2),
            Self::Blob => Some(3),
            Self::Tag => Some(4),
            Self::OfsDelta => Some(6),
            Self::RefDelta => Some(7),
            Self::Unknown(_) => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
            Self::OfsDelta => "ofs_delta",
            Self::RefDelta => "ref_delta",
            Self::Unknown(_) => "unknown",
        }
    }

    pub fn parse_name(name: &str) -> Option<Self> {
        Some(match name {
            "commit" => Self::Commit,
            "tree" => Self::Tree,
            "blob" => Self::Blob,
            "tag" => Self::Tag,
            _ => return None,
        })
    }

    pub fn is_delta(self) -> bool {
        matches!(self, Self::OfsDelta | Self::RefDelta)
    }
}

pub fn git_oid(kind: ObjectType, data: &[u8]) -> Oid {
    let name = match kind {
        ObjectType::Commit => b"commit".as_slice(),
        ObjectType::Tree => b"tree",
        ObjectType::Blob => b"blob",
        ObjectType::Tag => b"tag",
        _ => unreachable!("git oid only for leaf types"),
    };
    let mut hasher = Sha1::new();
    hasher.update(name);
    hasher.update(b" ");
    hasher.update(data.len().to_string().as_bytes());
    hasher.update(b"\0");
    hasher.update(data);
    hasher.finalize().into()
}

pub fn oid_hex(oid: &Oid) -> String {
    hex::encode(oid)
}

pub fn parse_oid(value: &str) -> Option<Oid> {
    let bytes = hex::decode(value.trim()).ok()?;
    bytes.try_into().ok()
}

pub fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("in-memory zlib compression");
    encoder.finish().expect("finish zlib compression")
}

#[derive(Debug, Clone)]
pub struct ZlibResult {
    pub data: Vec<u8>,
    pub consumed: usize,
    pub ended: bool,
    pub capped: bool,
    pub error: Option<String>,
}

pub fn zlib_decompress_limited(input: &[u8], declared: Option<u64>, hard_limit: usize) -> Result<ZlibResult, String> {
    let mut dec = Decompress::new(true);
    let mut out = Vec::new();
    let mut offset_in = 0usize;
    let mut ended = false;
    let mut capped = false;

    loop {
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let old_len = out.len();
        let reserve = match declared.and_then(|v| usize::try_from(v).ok()) {
            Some(size) if size > old_len => (size - old_len).clamp(1024, 1024 * 1024),
            _ => (out.len() + 1024).next_power_of_two().min(1024 * 1024),
        };
        out.resize(old_len + reserve, 0);
        let in_before_total = dec.total_in();
        let out_before_total = dec.total_out();
        let result = dec.decompress(
            &input[offset_in..],
            &mut out[old_len..],
            FlushDecompress::None,
        );
        offset_in += (dec.total_in() - in_before_total) as usize;
        let produced = (dec.total_out() - out_before_total) as usize;
        out.truncate(old_len + produced);
        let _ = (before_in, before_out);
        match result {
            Ok(flate2::Status::StreamEnd) => {
                ended = true;
                break;
            }
            Ok(_) => {
                if let Some(size) = declared.and_then(|v| usize::try_from(v).ok()) {
                    if out.len() > size {
                        capped = true;
                        return Err(format!(
                            "declared size {} was exceeded after decompressing {} bytes",
                            size,
                            out.len()
                        ));
                    }
                }
                if out.len() >= hard_limit {
                    capped = true;
                    return Err(format!("hard decompression limit {} reached", hard_limit));
                }
                if offset_in >= input.len() {
                    return Err("zlib stream ended without an explicit end marker".into());
                }
            }
            Err(err) => return Err(format!("zlib error at input byte {offset_in}: {err}")),
        }
    }

    let mut error = None;
    if let Some(size) = declared.and_then(|v| usize::try_from(v).ok()) {
        if out.len() != size {
            error = Some(format!(
                "size spoof: header declared {size} bytes but zlib produced {} bytes",
                out.len()
            ));
        }
    }
    let consumed = dec.total_in() as usize;
    Ok(ZlibResult { data: out, consumed, ended, capped, error })
}

pub fn read_pack_size(reader: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let first = *reader.get(pos).ok_or_else(|| "truncated size encoding".to_string())?;
    let mut size = u64::from(first & 0x0f);
    let mut shift = 4u32;
    pos += 1;
    let mut current = first;
    while current & 0x80 != 0 {
        current = *reader.get(pos).ok_or_else(|| "truncated continued size".to_string())?;
        size |= u64::from(current & 0x7f) << shift;
        shift += 7;
        pos += 1;
    }
    Ok((size, pos))
}

pub fn encode_pack_size(kind: ObjectType, size: u64) -> Vec<u8> {
    let code = kind.code().unwrap();
    let mut out = Vec::new();
    let mut value = size;
    let mut first = (value & 0x0f) as u8 | (code << 4);
    value >>= 4;
    if value != 0 { first |= 0x80; }
    out.push(first);
    while value != 0 {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 { byte |= 0x80; }
        out.push(byte);
    }
    out
}

pub fn encode_delta_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 { byte |= 0x80; }
        out.push(byte);
        if value == 0 { break; }
    }
    out
}

pub fn read_delta_varint(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(pos).ok_or_else(|| "truncated delta varint".to_string())?;
        result |= u64::from(byte & 0x7f) << shift;
        pos += 1;
        if byte & 0x80 == 0 { break; }
        shift += 7;
        if shift > 63 { return Err("delta varint too large".into()); }
    }
    Ok((result, pos))
}

pub fn encode_ofs_distance(mut distance: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut rest = distance >> 7;
    let mut byte = (distance & 0x7f) as u8;
    while rest > 0 {
        byte |= 0x80;
        bytes.push(byte);
        distance = rest - 1;
        byte = (distance & 0x7f) as u8;
        rest = distance >> 7;
    }
    bytes.push(byte);
    bytes.reverse();
    bytes
}

pub fn read_ofs_distance(data: &[u8], mut pos: usize) -> Result<(u64, usize), String> {
    let mut byte = *data.get(pos).ok_or_else(|| "truncated ofs-delta".to_string())?;
    let mut distance = u64::from(byte & 0x7f);
    pos += 1;
    while byte & 0x80 != 0 {
        byte = *data.get(pos).ok_or_else(|| "truncated ofs-delta continuation".to_string())?;
        distance = distance.wrapping_add(1).wrapping_shl(7) | u64::from(byte & 0x7f);
        pos += 1;
    }
    Ok((distance, pos))
}

pub fn preview_text(data: &[u8], limit: usize) -> String {
    let sample = &data[..data.len().min(limit)];
    let mut out = String::new();
    for byte in sample {
        if (0x20..=0x7e).contains(byte) || *byte == b'\n' || *byte == b'\t' {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    if data.len() > limit { out.push('…'); }
    out
}
